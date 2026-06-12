# Security Scanner — Combined Server

Single-server setup: Flask serves both API and frontend.
No API key exposure. No CORS issues. One deploy, one URL.

## Deploy

1. Push to GitHub
2. Render: New + > Web Service
3. Build: `pip install -r requirements.txt`
4. Start: `gunicorn -w 2 -t 65 app:app`

## Local Test

```bash
pip install -r requirements.txt
python app.py
# Open http://localhost:10000
```
