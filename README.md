## 🚀 Getting Started

Full instructions (Python setup, virtual environment, `.env` config, HashiCorp Vault, and Railway deployment) are all in **[STEP_BY_STEP_GUIDE.md](./STEP_BY_STEP_GUIDE.md)** — follow it in order, don't skip ahead.

Quick start (local, no Vault required):

```bash
git clone https://github.com/AdliFirdaus/vaultx.git
cd vaultx/backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
copy .env.example .env       # set USE_VAULT=false for local testing
python app.py
```

Then open http://localhost:5000/login

## 🌐 Live Demo

A hosted instance is running on Railway:

🔗 https://web-production-ed858a.up.railway.app

