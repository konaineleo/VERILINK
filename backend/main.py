"""VERIKLIK API. Run: uvicorn main:app --reload --port 8000"""
import os, time
from collections import defaultdict, deque
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from analyzer import analyze_url

app = FastAPI(title="VERIKLIK API")
origins = [o.strip() for o in os.getenv(
    "ALLOWED_ORIGINS", "https://veriklik.vercel.app,http://localhost:5500,http://127.0.0.1:5500").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["POST", "GET"],
                   allow_headers=["Content-Type"])
_hits = defaultdict(deque)  # prototype in-memory limiter: 30 requests/minute/IP


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


@app.get("/health")
def health():
    return {"status": "ok", "service": "VERIKLIK"}


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest, request: Request):
    ip, now = (request.client.host if request.client else "?"), time.time()
    q = _hits[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= 30:
        raise HTTPException(429, "Too many requests. Try again in a minute.")
    q.append(now)
    try:
        return analyze_url(req.url)
    except ValueError as e:
        raise HTTPException(422, str(e))
