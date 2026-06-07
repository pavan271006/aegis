# ─────────────────────────────────────────────────────────────────────────
#  AEGIS — one-shot deploy: FastAPI -> Cloud Run, React -> Firebase Hosting
#  Usage (PowerShell, from the repo root):
#     ./deploy.ps1 -ProjectId your-firebase-project-id -ApiKey "a-long-random-string"
# ─────────────────────────────────────────────────────────────────────────
param(
  [Parameter(Mandatory = $true)] [string]$ProjectId,
  [Parameter(Mandatory = $true)] [string]$ApiKey,
  [string]$Region = "us-central1",
  [string]$Service = "aegis-backend"
)

$ErrorActionPreference = "Stop"

Write-Host "==> Using project $ProjectId (region $Region)" -ForegroundColor Cyan
gcloud config set project $ProjectId

Write-Host "==> Enabling required Google Cloud APIs" -ForegroundColor Cyan
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com

Write-Host "==> Deploying backend to Cloud Run" -ForegroundColor Cyan
gcloud run deploy $Service `
  --source backend `
  --region $Region `
  --allow-unauthenticated `
  --min-instances 1 `
  --max-instances 1 `
  --set-env-vars "API_KEY=$ApiKey,RESPONSE_MODE=dry-run,GEOIP_ENABLED=true"

Write-Host "==> Building frontend" -ForegroundColor Cyan
Push-Location frontend
npm install
npm run build
Pop-Location

Write-Host "==> Deploying Firebase Hosting" -ForegroundColor Cyan
firebase use $ProjectId
firebase deploy --only hosting

Write-Host "==> Done. App: https://$ProjectId.web.app" -ForegroundColor Green
