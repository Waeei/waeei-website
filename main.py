import os
import urllib.request
from pathlib import Path
from datetime import datetime
import httpx
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, HttpUrl
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, DateTime, desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import Optional
from urllib.parse import urlparse

load_dotenv()


GSB_KEY = os.getenv("GSB_API_KEY")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")

app = FastAPI(title="Waaei Link Scanner")


db_path = os.getenv("DB_PATH", "WaaeiDB.db") 
DATABASE_URL = f"sqlite:///{db_path}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class URLCheck(Base):
    __tablename__ = "url_checks"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True, nullable=False)
    verdict = Column(String, nullable=False)
    explanation = Column(String, nullable=True)
    checked_at = Column(DateTime, default=datetime.utcnow, nullable=False)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:3000", "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


GITHUB_RAW = os.getenv("MALICIOUS_LIST_URL", "").strip()
LOCAL_DATA_DIR = Path(__file__).parent / "data"
LOCAL_DATA_DIR.mkdir(exist_ok=True)
MALICIOUS_FILE = LOCAL_DATA_DIR / "malicious_urls.txt"
MALICIOUS_SET = set()

def try_download_from_github():
    if not GITHUB_RAW:
        return False
    try:
        print("Downloading malicious list from:", GITHUB_RAW)
        with urllib.request.urlopen(GITHUB_RAW, timeout=20) as r:
            raw = r.read().decode("utf-8", errors="ignore")
        MALICIOUS_FILE.write_text(raw, encoding="utf-8")
        print("Saved malicious list to local file:", MALICIOUS_FILE)
        return True
    except Exception as e:
        print("Warning: could not download malicious list:", e)
        return False

def load_malicious_set():
    global MALICIOUS_SET
    MALICIOUS_SET = set()
    
    if MALICIOUS_FILE.exists():
        try:
            text = MALICIOUS_FILE.read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                u = line.lower().rstrip("/")
                MALICIOUS_SET.add(u)
            print("Loaded malicious entries locally:", len(MALICIOUS_SET))
            return
        except Exception as e:
            print("Warning: error reading local malicious file:", e)

    if GITHUB_RAW:
        ok = try_download_from_github()
        if ok and MALICIOUS_FILE.exists():
            return load_malicious_set()  

    print("Loaded malicious entries: 0 (no local file / download failed)")

def normalize_url_and_domain(u: str):
    u = (u or "").strip()
    if not u:
        return "", ""
    if not (u.startswith("http://") or u.startswith("https://")):
        u = "http://" + u  
    try:
        p = urlparse(u)
        domain = (p.netloc or "").lower()
        
        if ":" in domain:
            domain = domain.split(":")[0]
        url_norm = (p.geturl() or "").lower().rstrip("/")
        return url_norm, domain
    except Exception:
        return u.lower().rstrip("/"), u.lower().rstrip("/")

def is_in_malicious_list(url: str) -> bool:
    url_norm, domain = normalize_url_and_domain(url)
    if url_norm in MALICIOUS_SET:
        print(f"[DEBUG] matched exact url: {url_norm}")
        return True
    if domain in MALICIOUS_SET:
        print(f"[DEBUG] matched domain: {domain}")
        return True
    if domain.startswith("www.") and domain[4:] in MALICIOUS_SET:
        print(f"[DEBUG] matched domain without www: {domain[4:]}")
        return True
    for entry in MALICIOUS_SET:
        if entry and entry.startswith(".") and domain.endswith(entry):
            print(f"[DEBUG] matched suffix entry {entry} for {domain}")
            return True
        if domain.endswith(entry) and domain != entry:
            if domain.endswith("." + entry) or domain == entry:
                print(f"[DEBUG] matched suffix/simple entry {entry} for {domain}")
                return True
    return False

async def check_gsb(url: str):
    if not GSB_KEY:
        return {"provider": "gsb", "status": "skipped", "raw": None, "reason": "GSB_API_KEY missing"}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}"
    payload = {
        "client": {"clientId": "waaie", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(endpoint, json=payload)
            data = r.json() if r.content else {}
            return {"provider": "gsb", "status": "malicious" if data else "clean", "raw": data}
    except Exception as e:
        print("check_gsb error:", e)
        return {"provider": "gsb", "status": "error", "raw": None, "reason": str(e)}

async def check_urlscan(url: str):
    if not URLSCAN_KEY:
        return {"provider": "urlscan", "status": "skipped", "raw": None, "reason": "URLSCAN_API_KEY missing"}
    headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
    payload = {"url": url}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post("https://urlscan.io/api/v1/scan/", headers=headers, json=payload)
            if r.status_code in (200, 201):
                return {"provider": "urlscan", "status": "submitted", "raw": r.json()}
            else:
                return {"provider": "urlscan", "status": "error", "raw": r.text, "code": r.status_code}
    except Exception as e:
        print("check_urlscan error:", e)
        return {"provider": "urlscan", "status": "error", "raw": None, "reason": str(e)}

async def gpt_explain(verdict: str, url: str) -> str:
    """
    If OPENAI_KEY is present, call OpenAI Chat Completions (v1) via httpx.
    If not present, return a short local explanation in Arabic.
    """
    if not OPENAI_KEY:
        if verdict.upper() == "MALICIOUS":
            return "هذا الرابط تم تصنيفه كمحتوى خبيث بناءً على قواعد ومصادر التحليل (قائمة محلية/مستندات أمان). ننصح بعدم فتح الرابط أو إدخال أي بيانات."
        else:
            return "هذا الرابط يبدو آمناً بناءً على المصادر المتاحة حالياً. دائماً كن حذراً وتحقق من المرسِل وعلامات التحذير."
    try:
        endpoint = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {OPENAI_KEY}", "Content-Type": "application/json"}
        prompt = f"اشرح للمستخدم العربي ببساطة نتيجة فحص الرابط التالي ({url}) والسبب وراء تصنيفه كـ {verdict}."
        body = {
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 200,
            "temperature": 0.2,
        }
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(endpoint, headers=headers, json=body)
            if r.status_code == 200:
                data = r.json()
                text = data.get("choices", [{}])[0].get("message", {}).get("content") or ""
                return text.strip()
            else:
                print("OpenAI error:", r.status_code, r.text)
                return f"تعذّر إنشاء شرح (OpenAI returned {r.status_code})."
    except Exception as e:
        print("gpt_explain error:", e)
        return f"تعذّر إنشاء شرح: {e}"

class AnalyzeBody(BaseModel):
    url: HttpUrl

class URLItem(BaseModel):
    id: int
    url: str
    verdict: str
    checked_at: datetime
    explanation: Optional[str] = None

    class Config:
       from_attributes = True

@app.get("/test-gsb")
async def test_gsb():
    test_url = "http://testsafebrowsing.appspot.com/s/malware.html"
    return await check_gsb(test_url)

@app.get("/test-gpt")
async def test_gpt():
    try:
        msg = await gpt_explain("SAFE", "https://example.com")
        return {"status": "ok", "message": msg}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@app.get("/test-urlscan")
async def test_urlscan():
    return await check_urlscan("http://example.com")

@app.get("/")
def root():
    return {"ok": True, "service": "Waaei Backend"}

@app.post("/analyze-link")
async def analyze_link_post(body: AnalyzeBody, db: Session = Depends(get_db)):
    return await _analyze_and_store(str(body.url), db)

@app.get("/analyze-link")
async def analyze_link_get(url: str, db: Session = Depends(get_db)):
    if not url:
        raise HTTPException(status_code=400, detail="missing url parameter")
    return await _analyze_and_store(url, db)

async def _analyze_and_store(url: str, db: Session):
    print(f"[INFO] analyzing: {url}")
    if is_in_malicious_list(url):
        final_verdict = "MALICIOUS"
        gsb_result = {"provider": "local_list", "status": "malicious", "raw": None}
        urlscan_result = {"provider": "urlscan", "status": "skipped", "raw": None, "reason": "local list matched"}
    else:
        gsb_result = await check_gsb(url)
        urlscan_result = await check_urlscan(url)
        final_verdict = "MALICIOUS" if gsb_result.get("status") == "malicious" else "SAFE"

    try:
        gpt_explanation = await gpt_explain(final_verdict, url)
        record = URLCheck(url=url, verdict=final_verdict, explanation=gpt_explanation)
        db.add(record)
        db.commit()
        db.refresh(record)
    except Exception as e:
        print("DB save error:", e)
        gpt_explanation = f"تعذّر حفظ النتيجة: {e}"

    return JSONResponse({
        "url": url,
        "final_verdict": final_verdict,
        "gsb": gsb_result,
        "urlscan": urlscan_result,
        "explanation": gpt_explanation,
    })

@app.get("/history", response_class=HTMLResponse)
def get_history_html(db: Session = Depends(get_db)):
    records = db.query(URLCheck).order_by(desc(URLCheck.checked_at)).all()
    html = """
    <html lang='ar' dir='rtl'>
    <head>
        <meta charset="utf-8">
        <title>سجل الروابط - واعي</title>
        <style>
            body { font-family: Arial, sans-serif; background-color:#fff5f5; text-align:center; margin:40px; }
            table { border-collapse:collapse; margin:0 auto; width:90%; background:#c7ddde; box-shadow:0 2px 8px rgba(0,0,0,0.1); border-radius:8px; overflow:hidden;}
            th { background:#5a9695; color:#fff; padding:12px; font-size:16px;}
            td { padding:10px; border-bottom:1px solid #ddd; font-size:14px;}
            .safe { color:green; font-weight:bold; }
            .unsafe { color:red; font-weight:bold; }
        </style>
    </head>
    <body>
        <h2>سجل الروابط</h2>
        <table>
            <tr><th>الرابط</th><th>النتيجة</th><th>التاريخ</th></tr>
    """
    for r in records:
        icon = "✅" if r.verdict == "SAFE" else "❌"
        cls = "safe" if r.verdict == "SAFE" else "unsafe"
        html += f"<tr><td>{r.url}</td><td class='{cls}'>{icon} {r.verdict}</td><td>{r.checked_at}</td></tr>"
    html += "</table></body></html>"
    return HTMLResponse(content=html)

@app.get("/history-json")
def get_history_json(db: Session = Depends(get_db)):
    rows = db.query(URLCheck).order_by(desc(URLCheck.checked_at)).all()
    return [
        {"id": r.id, "url": r.url, "verdict": r.verdict, "checked_at": r.checked_at}
        for r in rows
    ]

@app.on_event("startup")
def on_startup():
    print("Starting Waaei backend...")
    load_malicious_set()
    Base.metadata.create_all(bind=engine)
    print("Startup complete.")


