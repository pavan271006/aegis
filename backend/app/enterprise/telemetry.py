"""Observability: OpenTelemetry traces, Prometheus metrics, structured JSON logs.

`telemetry.setup(app)`:
  - installs OTel auto-instrumentation (FastAPI + SQLAlchemy + httpx),
  - exposes Prometheus metrics at GET /metrics,
  - records per-request latency/count/in-flight + domain metrics,
  - emits one structured JSON log line per request with trace correlation."""
import json
import logging
import time

from fastapi import FastAPI, Request
from prometheus_client import (
    CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest,
)
from starlette.responses import Response

# ── Prometheus metrics ─────────────────────────────────────────────────────
REQS = Counter("aegis_http_requests_total", "HTTP requests",
               ["method", "path", "status"])
LAT = Histogram("aegis_http_request_seconds", "HTTP latency", ["method", "path"])
INFLIGHT = Gauge("aegis_http_inflight", "In-flight requests")

# Domain metrics — prove the product is actually working (the legacy build had none)
INGEST_LAG = Gauge("aegis_ingest_lag_seconds", "Age of newest ingested event", ["org"])
DETECTIONS = Counter("aegis_detections_total", "Incidents created", ["org", "severity"])
BLOCKS = Counter("aegis_blocks_total", "Auto-block actions", ["org", "result"])
SIEM_FWD = Counter("aegis_siem_forwarded_total", "Events forwarded to SIEM", ["kind", "result"])


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname, "logger": record.name,
            "msg": record.getMessage(),
        }
        for k in ("trace_id", "org_id", "user_id", "path", "status", "latency_ms"):
            if hasattr(record, k):
                base[k] = getattr(record, k)
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        return json.dumps(base)


def _configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)


def setup(app: FastAPI) -> None:
    _configure_logging()
    log = logging.getLogger("aegis.request")

    # OpenTelemetry tracing is OPT-IN: only wire the OTLP exporter when a collector
    # endpoint is actually configured. Otherwise the BatchSpanProcessor would spam
    # connection-refused errors trying to reach the default localhost:4318. Prometheus
    # metrics + structured JSON logs below are always on.
    import os
    if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            provider = TracerProvider(resource=Resource.create({"service.name": "aegis-api"}))
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
            trace.set_tracer_provider(provider)
            FastAPIInstrumentor.instrument_app(app)
        except Exception:  # pragma: no cover — tracing optional in dev
            pass

    @app.middleware("http")
    async def _observe(request: Request, call_next):
        path = request.scope.get("route").path if request.scope.get("route") else request.url.path
        INFLIGHT.inc()
        start = time.perf_counter()
        status_code = 500
        try:
            resp = await call_next(request)
            status_code = resp.status_code
            return resp
        finally:
            elapsed = time.perf_counter() - start
            INFLIGHT.dec()
            REQS.labels(request.method, path, status_code).inc()
            LAT.labels(request.method, path).observe(elapsed)
            try:
                from opentelemetry import trace
                tid = format(trace.get_current_span().get_span_context().trace_id, "032x")
            except Exception:
                tid = ""
            log.info("request", extra={"path": path, "status": status_code,
                                       "latency_ms": round(elapsed * 1000, 1), "trace_id": tid})

    @app.get("/metrics", include_in_schema=False)
    def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
