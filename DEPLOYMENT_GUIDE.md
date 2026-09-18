# 🌐 Global Deployment & Remote Access Guide
### Cyber Triage Tool - Multi-Device & Worldwide Internet Access

To allow other users, evaluators, or team members to use the **Cyber Triage Tool** and upload forensic evidence from **any mobile network (4G/5G), different Wi-Fi networks, or different locations**, you have two options:

---

## ⚡ Method 1: Instant Global Public HTTPS Tunnel (Zero Setup)

Run the tool on your computer and generate an instant, secure public `https://` link that works anywhere in the world.

### How to use:
1. Double-click **`run_public_tunnel.bat`** (or open PowerShell in the project directory and run):
   ```powershell
   python run_with_public_tunnel.py
   ```
2. The script will output a secure global URL, for example:
   ```text
   ======================================================================
   🚀 YOUR WEBSITE IS NOW LIVE ACROSS THE WORLD ON THE INTERNET!
   ======================================================================
   [+] 🌍 GLOBAL PUBLIC HTTPS URL:
       -> https://sample-cyber-triage-demo.trycloudflare.com
   ======================================================================
   ```
3. **Share this `https://...` link** with anyone!
   - They can open it on their iPhone, Android (via mobile data 4G/5G), or any laptop on any network.
   - They can upload evidence files, run AI triage, and download PDF reports in real time.
   - You can also scan the terminal QR code with your phone.

---

## ☁️ Method 2: Permanent 24/7 Cloud Deployment (Render.com - 100% Free)

If you want the project to stay online **24/7 on the cloud** even when your laptop is turned off:

### Step 1: Push Code to GitHub
1. Create a repository on GitHub (e.g. `https://github.com/pragatipatil441/Cyber-Triage-Tool` or a new repo).
2. Push all files from `Cyber-Triage-Tool-Advanced` to your repository:
   ```bash
   git init
   git add .
   git commit -m "Deploy Advanced Cyber Triage Platform"
   git branch -M main
   git remote add origin https://github.com/<your-username>/<your-repo-name>.git
   git push -u origin main
   ```

### Step 2: Deploy on Render (Free)
1. Go to [https://render.com](https://render.com) and sign in with GitHub.
2. Click **New +** &rarr; **Web Service**.
3. Select your GitHub repository.
4. Set the following settings:
   - **Name**: `cyber-triage-tool`
   - **Environment**: `Python 3`
   - **Region**: `Singapore` or nearest region
   - **Branch**: `main`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
   - **Plan**: `Free`
5. Click **Create Web Service**.
6. Render will automatically build the project and assign a permanent public domain:
   ```text
   https://cyber-triage-tool.onrender.com
   ```
7. Anyone across the globe can now visit your permanent URL anytime!

---

## 🐍 Method 3: PythonAnywhere (Free Python Hosting)
1. Sign up at [https://www.pythonanywhere.com](https://www.pythonanywhere.com).
2. Open a **Bash Console** and clone your repo:
   ```bash
   git clone https://github.com/<your-username>/<your-repo-name>.git
   cd <your-repo-name>
   pip install -r requirements.txt
   ```
3. Go to the **Web** tab &rarr; **Add a new web app** &rarr; select **Flask** (Python 3.10+).
4. Point the source directory to your repo and set the WSGI configuration file to import `app as application`.
5. Your app will be live at: `https://<your-username>.pythonanywhere.com`.

---

## 🔒 Security & Evidence Integrity on Public Deployments
- All evidence uploads are automatically hashed using **SHA-256**, **MD5**, and **SHA-1** to guarantee forensic integrity and prevent tampering.
- Large log uploads (up to 100 MB) are supported.
- Reports can be exported in PDF, JSON, CSV, and STIX 2.1 formats directly by any connected user.
