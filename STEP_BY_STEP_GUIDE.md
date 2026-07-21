# VaultX — Complete Step-by-Step Setup Guide

This is the **only** setup guide you need for VaultX — it covers everything
from running the system on your own PC, to enabling real HashiCorp Vault, to
deploying it publicly on Railway. Follow the three parts **in order, without
skipping** — each part builds on the one before it, so skipping ahead makes
it much harder to tell where a problem is actually coming from.

**Part 1 — Running Locally** gets the core app working with the simplest
possible setup (SQLite + a local encryption key). No Vault, no PostgreSQL,
no cloud account needed yet.

**Part 2 — HashiCorp Vault Setup** adds real Vault-based key management on
top of a system you've already confirmed works.

**Part 3 — Deploying to Railway** puts the system on a public URL, last,
since it has the most moving parts (GitHub, environment variables,
PostgreSQL, a live domain).

If you jump straight to Part 2 or Part 3 before finishing Part 1 and
something breaks, you won't know whether the problem is in the app itself,
in Vault, or in the deployment. Doing it in order lets you rule each layer
out completely before adding the next one.

---
---

# PART 1 — Running Locally

This part gets VaultX running on your own PC using the simplest path —
SQLite database + local encryption key fallback — so there is no HashiCorp
Vault or PostgreSQL setup needed yet. Don't skip the **Troubleshooting**
section near the end of Part 1 if something breaks — most issues are
already covered there.

## 1.0 Prerequisites

Install these first if you don't have them:

1. **Python 3.11** (recommended — matches `runtime.txt`)
   Download: https://www.python.org/downloads/release/python-3110/
   On the Windows installer, **tick "Add python.exe to PATH"** before
   clicking Install. This step is easy to miss and causes most setup
   problems.

2. Verify installation — open **Command Prompt** (or VS Code's Integrated
   Terminal, `Ctrl + \`` ) and run:
   ```
   python --version
   ```
   Should print `Python 3.11.x`. If it says "not recognized", Python isn't
   on PATH — reinstall and tick that box, or use `py` instead of `python`
   on Windows.

## 1.1 Extract the Project

Unzip `VaultX_Complete_Final.zip` somewhere simple, e.g. `C:\vaultx` (avoid
long OneDrive/Temp paths — they cause weird permission errors on Windows).

If you're using **VS Code**: `File > Open Folder` and select that `vaultx`
folder directly (not a single file inside it), then use the Integrated
Terminal (`Ctrl + \`` , or `View > Terminal`) for every command below instead
of opening a separate Command Prompt window.

Open a terminal **inside that folder**:
```
cd C:\vaultx
```

## 1.2 Create a Virtual Environment

A virtual environment keeps VaultX's Python packages separate from
everything else on your PC, which avoids version conflicts.

```
python -m venv venv
```

Activate it:

- **Windows (Command Prompt):**
  ```
  venv\Scripts\activate.bat
  ```
- **Windows (PowerShell):**
  ```
  venv\Scripts\Activate.ps1
  ```
  If PowerShell blocks it with a script-execution error, run this once first:
  ```
  Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
  ```
- **Mac/Linux:**
  ```
  source venv/bin/activate
  ```

You'll know it worked because your prompt now starts with `(venv)`. Every
step below assumes `(venv)` stays active — if you close the terminal,
reactivate it before continuing.

**Using VS Code?** After activating, VS Code usually shows a popup asking
you to select a Python interpreter for the workspace. Click it and choose
the one showing `('venv')` next to the path. If the popup doesn't appear:
press `Ctrl+Shift+P`, type "Python: Select Interpreter", and choose
`./venv/Scripts/python.exe` (Windows) or `./venv/bin/python` (Mac/Linux).
This makes sure IntelliSense, linting, and Run/Debug buttons all use the
same Python environment as your terminal.

## 1.3 Install Dependencies

```
cd backend
pip install -r requirements.txt
```

Wait for it to finish (installs Flask, cryptography, pyotp, etc). If you
hit errors here, jump to **Troubleshooting → Section A** at the end of
Part 1.

## 1.4 Set Up Environment Variables

Copy the example file:

- **Windows:** `copy .env.example .env`
- **Mac/Linux:** `cp .env.example .env`

Open `.env` in Notepad (or VS Code) and change it to this for the simplest
local run:

```env
SECRET_KEY=paste_a_random_string_here
FLASK_ENV=development
DATABASE_URL=
USE_VAULT=false
ALLOWED_ORIGINS=*
```

Generate a `SECRET_KEY` value by running:
```
python -c "import secrets; print(secrets.token_hex(32))"
```
Copy the long hex string it prints and paste it after `SECRET_KEY=`.

**`USE_VAULT=false`** is the key setting — it tells VaultX to skip
HashiCorp Vault entirely and auto-generate a local encryption key
(`backend/vaultx.key`) instead. This is the fastest path to a zero-error
first run. You'll switch this to real Vault in Part 2.

Leaving `DATABASE_URL` empty makes it fall back to SQLite
(`backend/vaultx.db`, created automatically) — no PostgreSQL install needed
yet either (PostgreSQL only comes into play in Part 3, on Railway).

## 1.5 Run the App

Still inside `backend/` with `(venv)` active:

```
python app.py
```

You should see something like:
```
* Running on http://127.0.0.1:5000
```

Leave this terminal window open — closing it stops the server.

## 1.6 Open It in Your Browser

Go to: **http://localhost:5000/login**

Do **not** double-click the HTML files directly from File Explorer or the
VS Code file tree — they are Flask/Jinja templates and only render
correctly when served by the running app from step 1.5. Opening them
directly shows raw `{% extends %}` text instead of the styled page.

## 1.7 Test the Full Flow (Do This in Order)

1. Click **Create account** → fill in name, email, and a password that has:
   uppercase + lowercase + a number + a special character (e.g. `Passw0rd!`),
   and confirm it in the second password field.
2. On the MFA setup page, scan the QR code with **Google Authenticator**
   (or Microsoft Authenticator / Authy) on your phone.
   - No phone handy? Use the manual key shown below the QR code with any
     desktop TOTP generator.
3. Enter the 6-digit code shown in your authenticator app → you land on
   the dashboard.
4. In the sidebar, try **My Files**: drag a file in (or click to browse or
   use "+ Upload File") → watch it encrypt/upload → download it again →
   confirm it opens correctly. Try the search box to filter by filename.
5. Click **Activity Log** in the sidebar: you should see REGISTER,
   MFA_SETUP_VERIFY, FILE_UPLOAD, and FILE_DOWNLOAD events logged with
   timestamps. Use the **Refresh** button any time to pull the latest events.
6. Click **Settings**: confirms which security features are active. Vault
   will show "LOCAL FALLBACK" — expected, since `USE_VAULT=false`.
7. Log out, then log back in with your email, password, and a **new** OTP
   code from your authenticator app (codes refresh every 30 seconds).
8. Optional — test **Forgot Password**: click "Forgot password?" on the
   login page, enter your email, and VaultX will show you a reset link
   directly on screen (there's no email server configured, so the link is
   shown instead of emailed — this is expected and explained on that page).
   Open the link, set a new password, and log in with it.

If all these steps pass, the system is running with zero errors. 🎉

## 1.8 Stopping and Restarting Later

To stop the server: go to the terminal running `python app.py` and press
`Ctrl+C`.

To run it again later:
```
cd C:\vaultx\backend
..\venv\Scripts\activate.bat
python app.py
```

Your account, files, and audit logs persist in `backend/vaultx.db` and
`backend/encrypted_storage/` between restarts — no need to register again.

## 1.9 Troubleshooting — Common Errors

### A. `pip install` fails / times out
- Make sure you're connected to the internet and no VPN/proxy is blocking
  `pypi.org`.
- Try upgrading pip first: `python -m pip install --upgrade pip`
- If one specific package fails (e.g. `psycopg2-binary` on some Windows
  setups), and you're only using SQLite locally, you can safely skip it:
  ```
  pip install Flask Flask-SQLAlchemy Flask-Login Flask-CORS Flask-Limiter bcrypt pyotp qrcode[pil] cryptography hvac python-dotenv Pillow Werkzeug gunicorn
  ```
  (this installs everything except the PostgreSQL driver, which you don't
  need for local SQLite use).

### B. `ModuleNotFoundError: No module named 'flask'` (or any module)
- Your virtual environment isn't activated. Look for `(venv)` at the start
  of your terminal prompt. If it's missing, redo step 1.2's activate
  command.

### C. `Address already in use` / port 5000 busy
- Something else is using port 5000 (common on macOS — AirPlay Receiver
  uses it).
- Either close that other program, or run VaultX on a different port:
  ```
  set PORT=5050          (Windows cmd)
  $env:PORT=5050          (PowerShell)
  export PORT=5050        (Mac/Linux)
  python app.py
  ```
  Then visit `http://localhost:5050/login` instead.

### D. QR code scans but the 6-digit code is always "invalid"
- Your phone's clock and your PC's clock are out of sync (TOTP is
  time-based). Enable automatic date/time on your phone (Settings → Date &
  Time → Automatic).
- Make sure you're typing the code **before** it refreshes (each code is
  valid ~30s).

### E. `sqlite3.OperationalError: unable to open database file`
- You're running `python app.py` from the wrong folder. You must be inside
  `backend/` when you run it (the app writes `vaultx.db` next to `app.py`).
  Run `cd backend` first if you haven't.

### F. Browser shows raw `{% extends %}` text instead of the page
- You opened the `.html` file directly (`file://...`) instead of going
  through the running Flask server. Always use `http://localhost:5000/...`
  URLs, never double-click the template files.

### G. Uploading a file does nothing / "File type not allowed"
- Check the file's extension isn't in the blocked list (`.exe .bat .php
  .sh` etc.) or outside the max size (50MB). This is intentional security
  behavior, not a bug — see the Settings page for the full policy.

### H. Forgot Password page shows a reset link instead of sending an email
- This is expected. VaultX doesn't have an SMTP/email server configured in
  this environment, so the reset link is shown directly on screen for local
  testing instead of being emailed. In a production deployment, you would
  wire up an email service (e.g. Flask-Mail with a Gmail app password) and
  send `reset_link` from `/api/auth/forgot-password` by email instead.

Once every step in Part 1 passes cleanly, move on to Part 2.

---
---

# PART 2 — HashiCorp Vault Setup

VaultX uses HashiCorp Vault to store the AES-256 master encryption key
**separately** from the application database. This ensures that even if
the database is compromised, encrypted files remain unreadable without
access to Vault.

If Vault is unreachable, the app automatically falls back to the local key
file from Part 1 (`backend/vaultx.key`) — that fallback is intended for
**development only** and is never suitable for production.

## 2.1 Install Vault (Local Development)

**macOS (Homebrew):**
```bash
brew tap hashicorp/tap
brew install hashicorp/tap/vault
```

**Linux (apt):**
```bash
wget -O - https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault
```

**Windows (Chocolatey):**
```powershell
choco install vault
```

## 2.2 Run Vault in Dev Mode

Dev mode runs Vault in-memory, unsealed, with a fixed root token — good
enough for FYP demos and local testing (not for production — see 2.6).

```bash
vault server -dev -dev-root-token-id="root"
```

Vault will print a message confirming it's running at
`http://127.0.0.1:8200` with root token `root`. Keep this terminal open.

In a **new terminal**, point the CLI at the dev server:

```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'
```
(On Windows PowerShell: `$env:VAULT_ADDR="http://127.0.0.1:8200"` and
`$env:VAULT_TOKEN="root"`)

## 2.3 Enable the KV v2 Secrets Engine

Dev mode enables `secret/` (KV v2) by default. Verify with:
```bash
vault secrets list
```
If it's not listed, enable it manually:
```bash
vault secrets enable -path=secret kv-v2
```

## 2.4 Generate and Store the AES-256 Master Key

Generate a random 256-bit (32-byte) key as hex:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Copy the output, then store it in Vault at the path VaultX expects
(`vaultx-key`, matching `VAULT_SECRET_PATH` in `.env`):
```bash
vault kv put secret/vaultx-key key="PASTE_YOUR_GENERATED_HEX_KEY_HERE"
```

Verify it was stored correctly:
```bash
vault kv get secret/vaultx-key
```
You should see a `key` field containing your hex string.

## 2.5 Configure VaultX to Use It

In `backend/.env` (the same file from Part 1, step 1.4), change it to:
```env
VAULT_ADDR=http://127.0.0.1:8200
VAULT_TOKEN=root
VAULT_SECRET_PATH=vaultx-key
USE_VAULT=true
```

Restart the Flask app (`Ctrl+C` then `python app.py` again) —
`encryption.py` will call
`client.secrets.kv.v2.read_secret_version(path='vaultx-key')` on every
encrypt/decrypt operation and use the returned key.

Check connectivity anytime via the app's built-in endpoint:
```
GET /api/vault/status
```
This is also shown live on the dashboard's **Settings** page — it should
now say "ACTIVE" instead of "LOCAL FALLBACK".

## 2.6 Production Considerations

Dev mode is **not safe for production** — it stores everything in memory
and unseals automatically. For a real deployment:

1. Run Vault in production mode with persistent storage (Raft or Consul
   backend).
2. Enable TLS on `VAULT_ADDR`.
3. Use a proper auth method (AppRole, not root tokens) with a
   narrowly-scoped policy that only allows reading `secret/data/vaultx-key`.
4. Unseal Vault using Shamir key shares distributed among trusted operators.
5. Rotate the AES key periodically and re-encrypt stored files if your
   threat model requires it.

For a Railway deployment in Part 3, `USE_VAULT=true` with a Vault Cloud
(HCP Vault) free-tier cluster is a reasonable middle ground if you want a
live Vault instance instead of the local fallback.

## 2.7 Fallback Behavior (What Happens If Vault Is Down)

`encryption.py`'s `get_encryption_key()` function:

1. If `USE_VAULT=true`, attempts to connect to Vault and read the secret.
2. If that fails for **any** reason (Vault sealed, unreachable, wrong
   token, missing secret), it logs a warning and falls back to
   `backend/vaultx.key`, generating that file with a fresh random key if it
   doesn't already exist.
3. This means the app **never crashes** due to Vault being unavailable —
   it degrades gracefully, which is important to demonstrate during your
   FYP presentation if live Vault connectivity fails.

**Important:** if you rely on the local fallback, make sure
`backend/vaultx.key` is **never committed to git** (it's already in
`.gitignore`) and is backed up separately, since losing it means all
encrypted files become permanently undecryptable.

Once Vault is connected and `/api/vault/status` shows "connected": true,
move on to Part 3.

---
---

# PART 3 — Deploying to Railway

This part walks through deploying VaultX to [Railway](https://railway.app)
using the included `Procfile`, `railway.json`, and `runtime.txt`. Only do
this after Part 1 (and, ideally, Part 2) are working cleanly on your own PC.

## 3.1 Push the Project to GitHub

Railway deploys from a GitHub repo.

```bash
cd vaultx
git init
git add .
git commit -m "Initial VaultX commit"
git branch -M main
git remote add origin https://github.com/<your-username>/vaultx.git
git push -u origin main
```

Double-check `.gitignore` is excluding `.env`, `*.db`, and
`backend/vaultx.key` before pushing — never commit secrets.

## 3.2 Create a New Railway Project

1. Go to [railway.app](https://railway.app) and log in.
2. Click **New Project → Deploy from GitHub repo**.
3. Select your `vaultx` repository.
4. Railway will detect `railway.json` and use Nixpacks with the build
   command `pip install -r backend/requirements.txt`.

## 3.3 Add a PostgreSQL Database

1. In your Railway project, click **New → Database → Add PostgreSQL**.
2. Railway automatically injects a `DATABASE_URL` environment variable into
   your web service — no manual copy-pasting needed.
3. `app.py` already handles Railway's `postgres://` prefix by rewriting it
   to `postgresql://` for SQLAlchemy — no changes needed on your end.

## 3.4 Set Environment Variables

In your Railway service settings → **Variables**, add:

| Variable | Value |
|---|---|
| `SECRET_KEY` | Output of `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `FLASK_ENV` | `production` |
| `VAULT_ADDR` | Your Vault server URL (or leave as-is to use local fallback) |
| `VAULT_TOKEN` | Your Vault token |
| `VAULT_SECRET_PATH` | `vaultx-key` |
| `USE_VAULT` | `true` or `false` |
| `ALLOWED_ORIGINS` | Your Railway app URL, e.g. `https://vaultx-production.up.railway.app` |

`DATABASE_URL` and `PORT` are set automatically by Railway — do not add
them manually.

## 3.5 Deploy

Railway deploys automatically on every push to `main`. You can also
trigger a manual deploy from the dashboard.

Railway uses:
- **Procfile**: `web: cd backend && gunicorn app:app --workers 2 --timeout 120 --bind 0.0.0.0:$PORT`
- **runtime.txt**: pins the Python version to `3.11.0`
- **railway.json**: defines the build command, start command, and a health
  check against `/login`

Once deployed, Railway gives you a public URL like:
```
https://vaultx-production.up.railway.app
```

## 3.6 Verify the Deployment

1. Visit `https://<your-app>.up.railway.app/register` and create a test
   account.
2. Scan the MFA QR code and confirm login works end-to-end.
3. Upload a small file, then download it again to confirm decryption and
   the SHA-256 integrity check both succeed.
4. Check `GET /api/vault/status` to confirm whether Vault is connected or
   the app is running on local-key fallback.
5. Check the **Activity Log** page on the dashboard to confirm audit
   events are being recorded (register, login, MFA, upload, download).

## 3.7 Common Issues

**"Application failed to respond" / 502 errors**
Check the Railway build logs — usually a missing dependency in
`requirements.txt` or the app crashing on startup because `DATABASE_URL`
isn't set yet (make sure the PostgreSQL plugin is attached).

**CORS errors in the browser console**
Set `ALLOWED_ORIGINS` to your exact Railway URL (no trailing slash), or
`*` for a quick test (not recommended for production).

**Files uploaded before this deploy are missing**
`encrypted_storage/` is local disk storage per Railway container — it is
**not persistent** across redeploys unless you attach a Railway Volume.
For a production FYP demo, either attach a volume mounted at
`backend/encrypted_storage`, or plan to re-upload test files after each
deploy.

**Vault unreachable from Railway**
If your Vault instance runs on `127.0.0.1` locally, it will not be
reachable from Railway's servers. For a live demo with Vault, either use
HCP Vault (cloud-hosted) and set `VAULT_ADDR` to its public endpoint, or
set `USE_VAULT=false` to intentionally demonstrate the local-key fallback
path during your presentation.

---

## You're Done

If Part 1, Part 2, and Part 3 all check out, VaultX is fully set up: running
locally, backed by real HashiCorp Vault key management, and deployed
publicly on Railway with zero errors.
