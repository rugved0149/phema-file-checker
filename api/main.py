from fastapi import FastAPI, UploadFile, File
from fastapi.concurrency import run_in_threadpool
import tempfile
import os
import time
from fastapi.middleware.cors import CORSMiddleware

from scanner.scanner import scan_file
from scanner.event_adapter import convert_analysis_to_events

app = FastAPI(title="PHEMA File Checker API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {
    ".txt", ".ps1", ".js", ".vbs", ".exe", ".bin", ".zip"
}


@app.get("/")
def health():
    return {"status": "PHEMA API running"}


@app.post("/scan")
async def scan(file: UploadFile = File(...)):

    if not file.filename:
        return {"error": "No file uploaded"}

    ext = os.path.splitext(file.filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        return {
            "error": "Unsupported file type",
            "allowed_types": list(ALLOWED_EXTENSIONS)
        }

    content = await file.read()

    if len(content) > MAX_FILE_SIZE:
        return {"error": "File too large (max 10MB)"}

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
            "scan_duration_sec": duration,
            "events": events
        }

    finally:
        os.remove(temp_path)
