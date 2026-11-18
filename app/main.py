from __future__ import annotations
import csv, io, json, hashlib, ipaddress, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import sqlite3

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
DB = ROOT / "threatlens.db"
app = FastAPI(title="ThreatLens", version="1.0.0", description="IOC enrichment and triage training platform")
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")

def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")

def parse_dt(value):
    if not value: return None
    try:
        return datetime.fromisoformat(value.replace("Z","+00:00")).astimezone(timezone.utc)
    except Exception:
        return None

def db_conn():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    with db_conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS iocs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, indicator TEXT NOT NULL, normalized TEXT NOT NULL,
          type TEXT NOT NULL, category TEXT, first_seen TEXT, last_seen TEXT, expires_at TEXT,
          confidence INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'Needs review',
          is_allowlisted INTEGER NOT NULL DEFAULT 0, allowlist_reason TEXT,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(normalized,type)
        );
        CREATE TABLE IF NOT EXISTS observations(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
          source TEXT NOT NULL, source_confidence INTEGER NOT NULL DEFAULT 0, evidence TEXT,
          observed_at TEXT NOT NULL, UNIQUE(ioc_id,source,evidence)
        );
        CREATE TABLE IF NOT EXISTS allowlist(
          value TEXT NOT NULL, type TEXT NOT NULL, reason TEXT, PRIMARY KEY(value,type)
        );
        """)
    seed_allowlist()
    seed_dataset()

def seed_allowlist():
    p=DATA/"allowlist.json"
    if not p.exists(): return
    with db_conn() as c:
        for item in json.loads(p.read_text(encoding="utf-8")):
            normalized, typ = normalize(item["value"], item["type"])
            c.execute("INSERT OR IGNORE INTO allowlist(value,type,reason) VALUES(?,?,?)",(normalized,typ,item.get("reason","")))

def normalize(value, declared_type=None):
    raw=(value or "").strip()
    if not raw: raise ValueError("Empty indicator")
    typ=(declared_type or "").lower().strip()
    if typ in ("ip","ipv4","ipv6") or not typ:
        try:
            ip=ipaddress.ip_address(raw)
            return str(ip), ("ipv4" if ip.version==4 else "ipv6")
        except ValueError:
            if typ in ("ip","ipv4","ipv6"): raise ValueError("Invalid IP address")
    if typ in ("domain","hostname") or (not typ and "://" not in raw and "/" not in raw and "." in raw):
        domain=raw.rstrip(".").lower()
        if len(domain)>253 or not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*",domain):
            raise ValueError("Invalid domain")
        return domain,"domain"
    if typ=="url" or "://" in raw:
        parts=urlsplit(raw)
        if parts.scheme.lower() not in ("http","https") or not parts.hostname: raise ValueError("Only valid HTTP/HTTPS URLs are supported")
        host=parts.hostname.lower()
        netloc=host
        if parts.port: netloc += f":{parts.port}"
        path=parts.path or "/"
        return urlunsplit((parts.scheme.lower(),netloc,path,parts.query,"")),"url"
    if typ in ("md5","sha1","sha256") or not typ:
        lengths={"md5":32,"sha1":40,"sha256":64}
        if typ in lengths and not re.fullmatch(r"[a-fA-F0-9]{"+str(lengths[typ])+r"}",raw): raise ValueError(f"Invalid {typ.upper()} hash")
        if not typ:
            for t,n in (("md5",32),("sha1",40),("sha256",64)):
                if len(raw)==n and re.fullmatch(r"[a-fA-F0-9]+",raw): return raw.lower(),t
        if typ in lengths: return raw.lower(),typ
    raise ValueError("Unsupported or ambiguous indicator. Specify type as ipv4, ipv6, domain, url, md5, sha1 or sha256.")

def determine_status(confidence, allowlisted, expired):
    if allowlisted: return "Allowlisted"
    if expired: return "Expired"
    if confidence >= 80: return "High priority"
    if confidence >= 50: return "Review"
    return "Unverified"

def recompute(ioc_id, c):
    row=c.execute("SELECT * FROM iocs WHERE id=?",(ioc_id,)).fetchone()
    if not row: return
    obs=c.execute("SELECT source,source_confidence,evidence FROM observations WHERE ioc_id=?",(ioc_id,)).fetchall()
    # Conservative score: highest source confidence plus limited corroboration bonus.
    distinct=len({o["source"] for o in obs})
    highest=max([o["source_confidence"] for o in obs] or [0])
    score=min(100, highest + min(15,max(0,distinct-1)*7))
    al=c.execute("SELECT reason FROM allowlist WHERE value=? AND type=?",(row["normalized"],row["type"])).fetchone()
    exp=parse_dt(row["expires_at"])
    expired=bool(exp and exp < datetime.now(timezone.utc))
    status=determine_status(score,bool(al),expired)
    c.execute("UPDATE iocs SET confidence=?,status=?,is_allowlisted=?,allowlist_reason=?,updated_at=? WHERE id=?",
              (score,status,1 if al else 0,al["reason"] if al else None,now_iso(),ioc_id))

def ingest_record(record):
    value=record.get("indicator") or record.get("value")
    typ=record.get("type")
    try: normalized, typ=normalize(value,typ)
    except ValueError as e: return {"accepted":False,"indicator":value,"error":str(e)}
    source=str(record.get("source") or "Imported file")[:120]
    category=str(record.get("category") or "Unclassified")[:120]
    evidence=str(record.get("evidence") or "")[:1000]
    try: source_conf=max(0,min(100,int(record.get("source_confidence",record.get("confidence",0)) or 0)))
    except Exception: source_conf=0
    first=record.get("first_seen") or now_iso()
    expires=record.get("expires_at") or None
    with db_conn() as c:
        existing=c.execute("SELECT id,first_seen,last_seen,expires_at FROM iocs WHERE normalized=? AND type=?",(normalized,typ)).fetchone()
        if existing:
            ioc_id=existing["id"]
            c.execute("UPDATE iocs SET last_seen=?,category=COALESCE(NULLIF(?,'Unclassified'),category),updated_at=? WHERE id=?",
                      (now_iso(),category,now_iso(),ioc_id))
            duplicate=True
        else:
            cur=c.execute("""INSERT INTO iocs(indicator,normalized,type,category,first_seen,last_seen,expires_at,confidence,status,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?)""",(str(value),normalized,typ,category,first,first,expires,0,"Needs review",now_iso(),now_iso()))
            ioc_id=cur.lastrowid; duplicate=False
        c.execute("INSERT OR IGNORE INTO observations(ioc_id,source,source_confidence,evidence,observed_at) VALUES(?,?,?,?,?)",
                  (ioc_id,source,source_conf,evidence,now_iso()))
        recompute(ioc_id,c)
        return {"accepted":True,"id":ioc_id,"duplicate":duplicate,"normalized":normalized,"type":typ}

def seed_dataset():
    with db_conn() as c:
        count=c.execute("SELECT COUNT(*) n FROM iocs").fetchone()["n"]
    if count: return
    p=DATA/"synthetic_iocs.csv"
    with p.open(newline="",encoding="utf-8") as f:
        for row in csv.DictReader(f): ingest_record(row)

def serialize_ioc(row):
    d=dict(row)
    d["observations"]=[]
    with db_conn() as c:
        d["observations"]=[dict(x) for x in c.execute("SELECT source,source_confidence,evidence,observed_at FROM observations WHERE ioc_id=? ORDER BY observed_at",(d["id"],))]
    d["source_count"]=len({x["source"] for x in d["observations"]})
    d["expired"]=bool(parse_dt(d.get("expires_at")) and parse_dt(d["expires_at"]) < datetime.now(timezone.utc))
    return d

@app.on_event("startup")
def startup(): init_db()

@app.get("/", response_class=HTMLResponse)
def home():
    return (ROOT/"static"/"index.html").read_text(encoding="utf-8")

@app.get("/api/health")
def health(): return {"status":"ok","app":"ThreatLens","database":"SQLite","synthetic_demo":True}

@app.get("/api/stats")
def stats():
    with db_conn() as c:
        total=c.execute("SELECT COUNT(*) n FROM iocs").fetchone()["n"]
        counts={r["status"]:r["n"] for r in c.execute("SELECT status,COUNT(*) n FROM iocs GROUP BY status")}
        types={r["type"]:r["n"] for r in c.execute("SELECT type,COUNT(*) n FROM iocs GROUP BY type")}
        obs=c.execute("SELECT COUNT(*) n FROM observations").fetchone()["n"]
    return {"total":total,"observations":obs,"statuses":counts,"types":types}

@app.get("/api/iocs")
def list_iocs(q:Optional[str]=None, status:Optional[str]=None, type:Optional[str]=None):
    sql="SELECT * FROM iocs WHERE 1=1"; args=[]
    if q: sql+=" AND (normalized LIKE ? OR category LIKE ?)"; args += [f"%{q}%",f"%{q}%"]
    if status: sql+=" AND status=?"; args.append(status)
    if type: sql+=" AND type=?"; args.append(type)
    sql+=" ORDER BY CASE status WHEN 'High priority' THEN 1 WHEN 'Review' THEN 2 WHEN 'Unverified' THEN 3 WHEN 'Expired' THEN 4 ELSE 5 END, confidence DESC"
    with db_conn() as c: rows=c.execute(sql,args).fetchall()
    return [serialize_ioc(r) for r in rows]

@app.get("/api/iocs/{ioc_id}")
def get_ioc(ioc_id:int):
    with db_conn() as c: row=c.execute("SELECT * FROM iocs WHERE id=?",(ioc_id,)).fetchone()
    if not row: raise HTTPException(404,"IOC not found")
    return serialize_ioc(row)

@app.post("/api/ingest")
async def ingest(file:UploadFile=File(...)):
    name=(file.filename or "").lower()
    raw=await file.read()
    if len(raw)>2_000_000: raise HTTPException(413,"File too large; maximum 2 MB")
    try:
        if name.endswith(".csv"):
            records=list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
        elif name.endswith(".json"):
            obj=json.loads(raw.decode("utf-8-sig"))
            records=obj if isinstance(obj,list) else obj.get("indicators",[])
        else: raise HTTPException(400,"Upload a CSV or JSON file. STIX bundle import is available via /api/import-stix.")
    except (UnicodeDecodeError,json.JSONDecodeError) as e: raise HTTPException(400,f"Could not parse file: {e}")
    results=[ingest_record(r) for r in records]
    return {"processed":len(results),"accepted":sum(1 for x in results if x["accepted"]),"duplicates":sum(1 for x in results if x.get("duplicate")),"rejected":[x for x in results if not x["accepted"]]}

@app.post("/api/demo/reset")
def reset_demo():
    with db_conn() as c:
        c.execute("DELETE FROM observations"); c.execute("DELETE FROM iocs"); c.execute("DELETE FROM allowlist")
    seed_allowlist(); seed_dataset()
    return {"message":"Synthetic demo data reloaded."}

@app.post("/api/allowlist")
def add_allowlist(payload:dict):
    try: normalized,typ=normalize(payload.get("indicator"),payload.get("type"))
    except ValueError as e: raise HTTPException(400,str(e))
    reason=str(payload.get("reason") or "Added by analyst")[:300]
    with db_conn() as c:
        c.execute("INSERT OR REPLACE INTO allowlist(value,type,reason) VALUES(?,?,?)",(normalized,typ,reason))
        row=c.execute("SELECT id FROM iocs WHERE normalized=? AND type=?",(normalized,typ)).fetchone()
        if row: recompute(row["id"],c)
    return {"indicator":normalized,"type":typ,"status":"Allowlisted"}

@app.delete("/api/allowlist")
def remove_allowlist(indicator:str,type:str):
    with db_conn() as c:
        c.execute("DELETE FROM allowlist WHERE value=? AND type=?",(indicator,type))
        row=c.execute("SELECT id FROM iocs WHERE normalized=? AND type=?",(indicator,type)).fetchone()
        if row: recompute(row["id"],c)
    return {"removed":True}

@app.post("/api/iocs/{ioc_id}/triage")
def analyst_triage(ioc_id:int,payload:dict):
    status=payload.get("status")
    allowed={"Needs review","Investigating","Benign","Confirmed malicious","Closed"}
    if status not in allowed: raise HTTPException(400,"Unsupported analyst status")
    with db_conn() as c:
        cur=c.execute("UPDATE iocs SET status=?,updated_at=? WHERE id=?",(status,now_iso(),ioc_id))
        if cur.rowcount==0: raise HTTPException(404,"IOC not found")
    return {"id":ioc_id,"analyst_status":status}

@app.get("/api/iocs/{ioc_id}/summary")
def summary(ioc_id:int):
    d=get_ioc(ioc_id)
    evidence=[o["evidence"] for o in d["observations"] if o["evidence"]]
    sources=sorted({o["source"] for o in d["observations"]})
    if d["is_allowlisted"]: action="No threat action recommended: indicator is on the analyst allowlist. Verify the allowlist entry remains valid."
    elif d["expired"]: action="Treat as historical intelligence. Revalidate with current sources before operational use."
    elif d["confidence"]>=80: action="High-priority review: correlate with internal telemetry and validate the supporting reports."
    elif d["confidence"]>=50: action="Investigate: seek independent corroboration and check relevant endpoint or network logs."
    else: action="Unverified: do not block or declare malicious based on this record alone. Gather more evidence."
    return {"title":"IOC Analyst Triage Summary","indicator":d["normalized"],"type":d["type"],"confidence":d["confidence"],"status":d["status"],"source_count":d["source_count"],"sources":sources,"evidence":evidence,"first_seen":d["first_seen"],"last_seen":d["last_seen"],"expires_at":d["expires_at"],"allowlisted":bool(d["is_allowlisted"]),"expired":d["expired"],"recommended_action":action,"disclaimer":"Training assessment only. Confidence is an indicative heuristic, not proof of maliciousness. Analyst validation is required."}

@app.get("/api/export/csv")
def export_csv():
    with db_conn() as c: rows=c.execute("SELECT * FROM iocs ORDER BY id").fetchall()
    out=io.StringIO(); fields=["id","normalized","type","category","confidence","status","first_seen","last_seen","expires_at","is_allowlisted"]
    w=csv.DictWriter(out,fieldnames=fields); w.writeheader()
    for r in rows: w.writerow({k:r[k] for k in fields})
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=threatlens_iocs.csv"})

@app.get("/api/export/json")
def export_json():
    return JSONResponse([serialize_ioc(r) for r in db_conn().execute("SELECT * FROM iocs ORDER BY id").fetchall()])

@app.get("/api/export/stix")
def export_stix():
    objects=[]
    with db_conn() as c: rows=c.execute("SELECT * FROM iocs").fetchall()
    for n,r in enumerate(rows,1):
        typ=r["type"]
        if typ in ("ipv4","ipv6"): pattern=f"[{typ}-addr:value = '{r['normalized']}']"
        elif typ=="domain": pattern=f"[domain-name:value = '{r['normalized']}']"
        elif typ=="url": pattern=f"[url:value = '{r['normalized']}']"
        else: pattern=f"[file:hashes.'{typ.upper()}' = '{r['normalized']}']"
        objects.append({"type":"indicator","spec_version":"2.1","id":f"indicator--11111111-1111-4111-8111-{n:012d}","created":r["created_at"],"modified":r["updated_at"],"name":f"ThreatLens IOC {r['id']}","description":f"Status: {r['status']}. Synthetic/demo platform record; validate before operational use.","pattern":pattern,"pattern_type":"stix","valid_from":r["first_seen"],"confidence":r["confidence"]})
    return {"type":"bundle","id":"bundle--11111111-1111-4111-8111-111111111111","objects":objects}

@app.get("/api/allowlist")
def list_allowlist():
    with db_conn() as c: return [dict(r) for r in c.execute("SELECT * FROM allowlist ORDER BY type,value")]

@app.get("/api/docs-link")
def docs_link(): return {"openapi":"/docs"}
