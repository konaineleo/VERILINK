# VERIKLIK
Phishing and malicious-link detection: Chrome extension + FastAPI backend + static frontend.

## Run locally (Windows PowerShell, from this folder)
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
In a second terminal: `cd frontend; python -m http.server 5500`
Then open `chrome://extensions`, enable Developer mode, **Load unpacked** → the `extension` folder.

## Tests
`cd backend; pytest`

## Scoring (0–100)
IP host +30, user info +25, brand in subdomain +25, punycode +20, brand+text domain +15, many subdomains +10, unusual port +10, very long URL +10 (>100: +5), double encoding +10 (heavy encoding +5), HTTP +5.
0–19 Low Risk, 20–49 Suspicious, 50+ High Risk. Low Risk is never "safe".

## Privacy
The extension passes the link as `?url=` to the scanner; the page removes it from the address bar immediately, but it may remain in history. Production should use a single-use scan token.
The extension needs `http(s)://*/*` host access in its content script so it can see link clicks on any page; it requests no other permissions and stores nothing.

## Deploy
Frontend: deploy `frontend/` to Vercel (set `window.VERIKLIK_API` to your API URL). Backend: a Python host such as Render or Railway (`uvicorn main:app --host 0.0.0.0 --port $PORT`), with `ALLOWED_ORIGINS` set to the frontend origin. Update `FRONTEND_URL` in the extension. Not yet deployed.

## Known limitations / remaining
No threat-intel provider yet (adapter `threat_intel.py` not written), no ML, no single-use tokens, in-memory rate limit, approximate registered-domain detection, extension and frontend not yet browser-tested.
