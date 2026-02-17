from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from pathlib import Path
import tempfile
import os
import time

from scanner.scanner import scan_file
from scanner.event_adapter import convert_analysis_to_events

app = FastAPI(title="PHEMA File Checker")

# Allow frontend access (safe for demo)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_FILE = BASE_DIR.parent / "frontend" / "index.html"

MAX_FILE_SIZE = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {
    ".txt", ".ps1", ".js", ".vbs", ".exe", ".bin", ".zip"
}


@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    return FRONTEND_FILE.read_text(encoding="utf-8")


@app.post("/scan")
async def scan(file: UploadFile = File(...)):

    ext = os.path.splitext(file.filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        return {"error": "Unsupported file type"}

    content = await file.read()

    if len(content) > MAX_FILE_SIZE:
        return {"error": "File too large"}

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(content)
        temp_path = tmp.name

    try:
        start = time.time()

        raw = await run_in_threadpool(scan_file, temp_path)
        events = convert_analysis_to_events(raw)

        duration = round(time.time() - start, 3)

        return {
            "filename": file.filename,
            "size_kb": round(len(content) / 1024, 2),
            "scan_time_sec": duration,
            "events": events
        }

    finally:
        os.remove(temp_path)
