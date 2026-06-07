#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────
#  AEGIS — one-shot deploy: FastAPI -> Cloud Run, React -> Firebase Hosting
#  Usage (from the repo root):
#     ./deploy.sh <firebase-project-id> "<a-long-random-api-key>"
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

PROJECT_ID="${1:?Usage: ./deploy.sh <project-id> <api-key>}"
API_KEY="${2:?Usage: ./deploy.sh <project-id> <api-key>}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-aegis-backend}"

echo "==> Using project $PROJECT_ID (region $REGION)"
gcloud config set project "$PROJECT_ID"

echo "==> Enabling required Google Cloud APIs"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com

echo "==> Deploying backend to Cloud Run"
gcloud run deploy "$SERVICE" \
  --source backend \
  --region "$REGION" \
  --allow-unauthenticated \
  --min-instances 1 \
  --max-instances 1 \
  --set-env-vars "API_KEY=$API_KEY,RESPONSE_MODE=dry-run,GEOIP_ENABLED=true"

echo "==> Building frontend"
( cd frontend && npm install && npm run build )

echo "==> Deploying Firebase Hosting"
firebase use "$PROJECT_ID"
firebase deploy --only hosting

echo "==> Done. App: https://$PROJECT_ID.web.app"
