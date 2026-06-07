"""Background scheduler for periodic jobs.

Uses APScheduler to run:
  - monitoring_job: check all sites every N minutes
  - expiry_job: expire stale blocks every 5 minutes
  - digest_job: send weekly Telegram digest (configurable cron)
"""
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from ..config import settings
from ..database import SessionLocal

log = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None


def _monitoring_job() -> None:
    """Check all registered sites."""
    from ..models import Site
    from . import monitoring as mon_svc

    db = SessionLocal()
    try:
        sites = db.query(Site).all()
        for site in sites:
            try:
                mon_svc.check_site(db, site)
            except Exception:  # noqa: BLE001
                log.exception("monitoring_job failed for site %s", site.id)
    finally:
        db.close()


def _expiry_job() -> None:
    """Expire blocks past their TTL."""
    from . import responder

    db = SessionLocal()
    try:
        expired = responder.expire_blocks(db)
        if expired:
            log.info("Expired blocks for IPs: %s", expired)
    finally:
        db.close()


def _digest_job() -> None:
    """Send weekly Telegram digest."""
    from ..integrations import telegram
    from . import scoring

    db = SessionLocal()
    try:
        stats = scoring.compute(db)
        telegram.weekly_digest(stats)
    finally:
        db.close()


def start() -> BackgroundScheduler:
    """Create and start the background scheduler.  Safe to call multiple times
    (returns the existing scheduler on subsequent calls)."""
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    _scheduler = BackgroundScheduler(daemon=True)

    # Site monitoring every N minutes
    _scheduler.add_job(
        _monitoring_job,
        trigger=IntervalTrigger(minutes=settings.monitoring_interval_minutes),
        id="monitoring_job",
        replace_existing=True,
    )

    # Block expiry every 5 minutes
    _scheduler.add_job(
        _expiry_job,
        trigger=IntervalTrigger(minutes=5),
        id="expiry_job",
        replace_existing=True,
    )

    # Weekly digest (parse cron expression from settings)
    parts = settings.digest_cron.split()
    if len(parts) == 5:
        _scheduler.add_job(
            _digest_job,
            trigger=CronTrigger(
                minute=parts[0], hour=parts[1], day=parts[2],
                month=parts[3], day_of_week=parts[4],
            ),
            id="digest_job",
            replace_existing=True,
        )

    _scheduler.start()
    log.info("Scheduler started (%d jobs)", len(_scheduler.get_jobs()))
    return _scheduler


def stop() -> None:
    """Shut down the scheduler gracefully."""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        log.info("Scheduler stopped")
