import asyncio, os, time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse
import httpx, psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from passlib.hash import bcrypt

BASE=Path(__file__).resolve().parent.parent
DATABASE_URL=os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL","")
CRON_SECRET=os.getenv("CRON_SECRET","")
SECRET=os.getenv("NETWATCH_SECRET","netwatch-change-me")
if os.getenv("VERCEL") and SECRET=="netwatch-change-me": raise RuntimeError("Definissez NETWATCH_SECRET")
ADMIN_EMAIL=os.getenv("NETWATCH_ADMIN_EMAIL","admin@netwatch.local").strip().lower()
ADMIN_PASSWORD=os.getenv("NETWATCH_ADMIN_PASSWORD","Admin123!")
templates=Jinja2Templates(directory=str(BASE/"templates"))

class DB:
    def __init__(s): s.c=psycopg.connect(DATABASE_URL,row_factory=dict_row)
    def execute(s,q,p=None): return s.c.execute(q.replace("?","%s"),p)
    def commit(s): s.c.commit()
    def close(s): s.c.close()
_ready=False
def conn():
    global _ready
    c=DB()
    if not _ready: init_db(c); _ready=True
    return c
def iso():
    return datetime.now(timezone.utc).isoformat()
def init_db(c):
    c.c.execute("""
    CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,email TEXT UNIQUE,password_hash TEXT);
    CREATE TABLE IF NOT EXISTS monitors(
      id SERIAL PRIMARY KEY,name TEXT,target TEXT,kind TEXT,"interval" INTEGER DEFAULT 30,
      enabled INTEGER DEFAULT 1,created_at TEXT,description TEXT DEFAULT '',group_name TEXT DEFAULT 'Default'
    );
    CREATE TABLE IF NOT EXISTS checks(
      id SERIAL PRIMARY KEY,monitor_id INTEGER REFERENCES monitors(id) ON DELETE CASCADE,checked_at TEXT,status INTEGER,
      latency_ms DOUBLE PRECISION,detail TEXT
    );
    CREATE INDEX IF NOT EXISTS checks_mon_idx ON checks(monitor_id,id);
    """)
    if not c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        c.execute("INSERT INTO users(email,password_hash) VALUES(?,?)",(ADMIN_EMAIL,bcrypt.hash(ADMIN_PASSWORD)))
    c.commit()

def auth(r): return bool(r.session.get("user_id"))
def guard(r):
    if not auth(r): return RedirectResponse("/login",303)

async def check(m):
    start=time.perf_counter(); ok=0; detail=""
    try:
        if m["kind"]=="http":
            async with httpx.AsyncClient(follow_redirects=True,timeout=8) as x:
                res=await x.get(m["target"])
            ok=int(res.status_code<400); detail=f"HTTP {res.status_code}"
        elif m["kind"]=="tcp":
            host,port=m["target"].rsplit(":",1)
            rd,w=await asyncio.wait_for(asyncio.open_connection(host,int(port)),5)
            w.close(); await w.wait_closed(); ok=1; detail="TCP connected"
        else:
            detail="Type non supporté sur Vercel (ping)"
    except Exception as e: detail=str(e)[:300]
    return ok,round((time.perf_counter()-start)*1000,2) if ok else None,detail

async def run_due():
    c=conn(); now=datetime.now(timezone.utc)
    mons=c.execute("""SELECT m.*,(SELECT MAX(checked_at) FROM checks WHERE monitor_id=m.id) AS last_at
      FROM monitors m WHERE enabled=1""").fetchall()
    due=[m for m in mons if not m["last_at"] or (now-datetime.fromisoformat(m["last_at"])).total_seconds()>=m["interval"]-5]
    sem=asyncio.Semaphore(20)
    async def one(m):
        async with sem: return m,await check(m)
    for m,(ok,lat,detail) in await asyncio.gather(*[one(m) for m in due]):
        c.execute("INSERT INTO checks(monitor_id,checked_at,status,latency_ms,detail) VALUES(?,?,?,?,?)",(m["id"],iso(),ok,lat,detail))
    if now.minute==0: c.execute("DELETE FROM checks WHERE checked_at < ?",((now-timedelta(days=30)).isoformat(),))
    c.commit(); c.close(); return len(due)

app=FastAPI(title="NetWatch V2")
@app.get("/api/cron")
async def cron(r:Request):
    if not CRON_SECRET or r.headers.get("authorization")!=f"Bearer {CRON_SECRET}": raise HTTPException(401)
    return {"checked":await run_due()}
app.add_middleware(SessionMiddleware,secret_key=SECRET,max_age=86400)

@app.get("/",response_class=HTMLResponse)
async def dashboard(r:Request):
    g=guard(r)
    if g:return g
    c=conn()
    mons=c.execute("""SELECT m.*,ch.status,ch.latency_ms,ch.checked_at FROM monitors m
      LEFT JOIN checks ch ON ch.id=(SELECT MAX(id) FROM checks WHERE monitor_id=m.id) ORDER BY m.id DESC""").fetchall()
    total=len(mons); up=sum(x["status"]==1 for x in mons); down=sum(x["status"]==0 for x in mons)
    avg=c.execute("SELECT AVG(latency_ms) a FROM checks WHERE status=1").fetchone()["a"] or 0
    c.close()
    return templates.TemplateResponse("dashboard.html",{"request":r,"monitors":mons,"total":total,"up":up,"down":down,"avg":round(avg,2)})

@app.get("/login",response_class=HTMLResponse)
async def login_page(r:Request): return templates.TemplateResponse("login.html",{"request":r,"error":None})
@app.post("/login",response_class=HTMLResponse)
async def login(r:Request,email:str=Form(...),password:str=Form(...)):
    c=conn(); u=c.execute("SELECT * FROM users WHERE email=?",(email.strip().lower(),)).fetchone(); c.close()
    if not u or not bcrypt.verify(password,u["password_hash"]):
        return templates.TemplateResponse("login.html",{"request":r,"error":"Identifiants incorrects"},status_code=401)
    r.session["user_id"]=u["id"];r.session["email"]=u["email"];return RedirectResponse("/",303)
@app.get("/logout")
async def logout(r:Request): r.session.clear();return RedirectResponse("/login",303)

@app.get("/admin",response_class=HTMLResponse)
async def admin(r:Request):
    g=guard(r)
    if g:return g
    c=conn(); mons=c.execute("SELECT * FROM monitors ORDER BY id DESC").fetchall();c.close()
    return templates.TemplateResponse("admin.html",{"request":r,"monitors":mons})
@app.post("/admin/add")
async def add(r:Request,name:str=Form(...),target:str=Form(...),kind:str=Form(...),interval:int=Form(30),group_name:str=Form("Default"),description:str=Form("")):
    g=guard(r)
    if g:return g
    if kind not in ("http","tcp"):raise HTTPException(400)
    if kind=="http" and urlparse(target).scheme not in ("http","https"):raise HTTPException(400,"URL invalide")
    c=conn();c.execute("INSERT INTO monitors(name,target,kind,\"interval\",created_at,description,group_name) VALUES(?,?,?,?,?,?,?)",
        (name.strip(),target.strip(),kind,max(10,min(interval,3600)),iso(),description.strip(),group_name.strip() or "Default"))
    c.commit();c.close();return RedirectResponse("/admin",303)
@app.post("/admin/delete/{mid}")
async def delete(r:Request,mid:int):
    g=guard(r)
    if g:return g
    c=conn();c.execute("DELETE FROM monitors WHERE id=?",(mid,));c.commit();c.close();return RedirectResponse("/admin",303)
@app.post("/admin/toggle/{mid}")
async def toggle(r:Request,mid:int):
    g=guard(r)
    if g:return g
    c=conn();c.execute("UPDATE monitors SET enabled=1-enabled WHERE id=?",(mid,));c.commit();c.close();return RedirectResponse("/admin",303)

@app.get("/monitor/{mid}",response_class=HTMLResponse)
async def monitor(r:Request,mid:int):
    g=guard(r)
    if g:return g
    c=conn();m=c.execute("SELECT * FROM monitors WHERE id=?",(mid,)).fetchone()
    if not m: raise HTTPException(404)
    rows=c.execute("SELECT * FROM checks WHERE monitor_id=? ORDER BY checked_at DESC LIMIT 100",(mid,)).fetchall()
    c.close()
    total=len(rows); ok=sum(x["status"] for x in rows)
    uptime=(ok/total*100) if total else 0
    loss=(1-ok/total)*100 if total else 0
    avg=sum(x["latency_ms"] for x in rows if x["latency_ms"] is not None)/(sum(x["latency_ms"] is not None for x in rows) or 1)
    return templates.TemplateResponse("monitor.html",{"request":r,"m":m,"rows":rows,"uptime":round(uptime,2),"loss":round(loss,2),"avg":round(avg,2)})

@app.get("/api/monitor/{mid}/history")
async def history(r:Request,mid:int,hours:int=24):
    if not auth(r):raise HTTPException(401)
    hours=max(1,min(hours,720))
    c=conn(); rows=c.execute("""SELECT checked_at,status,latency_ms FROM checks
      WHERE monitor_id=? AND checked_at >= ? ORDER BY checked_at""",
      (mid,(datetime.now(timezone.utc)-timedelta(hours=hours)).isoformat())).fetchall();c.close()
    return [dict(x) for x in rows]
