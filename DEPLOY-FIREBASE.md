# Deploying AEGIS to Firebase + Cloud Run

AEGIS has two parts that get hosted separately:

| Part | What it is | Where it runs |
|------|------------|---------------|
| Frontend | React / Vite static build | **Firebase Hosting** |
| Backend | FastAPI (Python) container | **Google Cloud Run** |

Firebase Hosting **rewrites** route `/api/**` and `/health` to the Cloud Run
service, so the whole app is served from one origin
(`https://<project>.web.app`). No CORS, no separate API URL — the frontend's
relative `/api` calls just work.

```
Browser ──▶ https://<project>.web.app
              ├── /            → Firebase Hosting (React app)
              ├── /assets/**   → Firebase Hosting (JS/CSS)
              └── /api/**      → Cloud Run (FastAPI)  ← rewrite in firebase.json
```

---

## 1. Prerequisites (one time)

1. **A Firebase project.** Create one at <https://console.firebase.google.com>.
   A Firebase project *is* a Google Cloud project — note its **Project ID**.
2. **Blaze (pay-as-you-go) billing.** Cloud Run and Hosting→Cloud Run rewrites
   require it. Low usage stays within the free allowances, but a card is required.
3. **CLIs installed:**
   ```bash
   npm install -g firebase-tools          # Firebase CLI
   # Google Cloud SDK (gcloud): https://cloud.google.com/sdk/docs/install
   ```
4. **Log in:**
   ```bash
   firebase login
   gcloud auth login
   ```

---

## 2. One-command deploy

From the repo root (`aegis-lite/`):

**Windows / PowerShell**
```powershell
./deploy.ps1 -ProjectId your-project-id -ApiKey "paste-a-long-random-string"
```

**macOS / Linux / Git Bash**
```bash
chmod +x deploy.sh
./deploy.sh your-project-id "paste-a-long-random-string"
```

The script enables the needed APIs, deploys the backend to Cloud Run, builds the
frontend, and deploys Hosting. When it finishes, open
**`https://your-project-id.web.app`** and sign in with `admin@aegis.internal` /
`admin123`.

---

## 3. Manual deploy (if you prefer step by step)

```bash
# point the Firebase CLI at your project (writes .firebaserc)
firebase use --add            # pick your project, alias it "default"
gcloud config set project YOUR_PROJECT_ID

# enable services
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com

# --- backend → Cloud Run (service name MUST be "aegis-backend" to match firebase.json) ---
gcloud run deploy aegis-backend \
  --source backend \
  --region us-central1 \
  --allow-unauthenticated \
  --min-instances 1 --max-instances 1 \
  --set-env-vars API_KEY=YOUR_RANDOM_KEY,RESPONSE_MODE=dry-run,GEOIP_ENABLED=true

# --- frontend → Firebase Hosting ---
cd frontend && npm install && npm run build && cd ..
firebase deploy --only hosting
```

> The Cloud Run **service name** (`aegis-backend`) and **region**
> (`us-central1`) must match the values in `firebase.json`. If you change one,
> change both.

---

## 4. Important notes

**Data persistence.** The backend defaults to SQLite, and Cloud Run's disk is
**ephemeral** — data resets whenever the instance recycles. `--min-instances 1`
keeps one instance warm so data survives during a demo, but for anything real,
provision **Cloud SQL (Postgres)** and pass its URL:
```bash
gcloud run services update aegis-backend --region us-central1 \
  --set-env-vars DATABASE_URL="postgresql+psycopg2://USER:PASS@/aegis?host=/cloudsql/INSTANCE"
```

**Scheduler.** The monitoring scheduler runs in-process. Keep
`--max-instances 1` so scheduled jobs don't run in duplicate across instances.

**Security before real use.**
- Change the seeded passwords (`admin123`, etc.) — they're created on first boot in `backend/app/main.py`.
- Use a long random `API_KEY` (it also signs the login JWTs).
- Cloud Run is deployed `--allow-unauthenticated` because Firebase Hosting calls it publicly; auth is enforced inside the app via login + roles.

**Cost.** `--min-instances 1` means one always-on instance (small but non-zero
cost). Drop it to `--min-instances 0` to scale to zero and pay only per request
— at the cost of a cold start and SQLite data resetting between requests.

---

## 5. Redeploying later

```bash
# backend code changed:
gcloud run deploy aegis-backend --source backend --region us-central1

# frontend code changed:
cd frontend && npm run build && cd .. && firebase deploy --only hosting
```

---

## 6. Continuous deployment with GitHub Actions

`.github/workflows/deploy.yml` deploys **automatically on every push to
`main`** (backend → Cloud Run, frontend → Firebase Hosting). You can also run it
manually from the Actions tab (`workflow_dispatch`).

### a. Push the repo to GitHub (if it isn't already)
```bash
git init
git add .
git commit -m "AEGIS: enterprise UI + Firebase/Cloud Run deploy"
git branch -M main
git remote add origin https://github.com/<you>/aegis.git
git push -u origin main
```

### b. Create a deploy service account and key
```bash
PROJECT_ID=your-project-id
gcloud iam service-accounts create aegis-deployer --project "$PROJECT_ID"
SA="aegis-deployer@$PROJECT_ID.iam.gserviceaccount.com"
for r in run.admin iam.serviceAccountUser cloudbuild.builds.editor \
         artifactregistry.admin storage.admin firebasehosting.admin \
         serviceusage.serviceUsageAdmin; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA" --role="roles/$r"
done
gcloud iam service-accounts keys create key.json --iam-account "$SA"
```

### c. Add three GitHub repository secrets
*(repo → Settings → Secrets and variables → Actions → New repository secret)*

| Secret | Value |
|--------|-------|
| `GCP_PROJECT_ID` | your project id |
| `GCP_SA_KEY` | the **entire contents** of `key.json` |
| `AEGIS_API_KEY` | a long random string |

Delete `key.json` locally afterward (`rm key.json`) — it's a credential.

### d. Done
Push to `main` (or hit **Run workflow**). The Action enables the APIs, deploys
the backend to Cloud Run, builds the frontend, and publishes Hosting. Watch it
under the repo's **Actions** tab.

> The existing `ci.yml` (detection smoke test) keeps running on PRs; `deploy.yml`
> only runs on pushes to `main`, so tests gate before deploys if you require PRs.
