import os
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from services.gophish_client import trigger_random_campaign

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()

def start_scheduler():
    """
    Starts the APScheduler background tasks.
    """
    # 1. Delay Mode: Phishing Campaign Trigger
    # Trigger a campaign randomly or on a specific schedule.
    # For demonstration, runs every Tuesday at 10 AM:
    # scheduler.add_job(trigger_random_campaign, 'cron', day_of_week='tue', hour=10, id='phishing_campaign_job')
    
    # Or, run every 24 hours just to see it work:
    scheduler.add_job(trigger_random_campaign, 'interval', hours=24, id='phishing_campaign_job')

    # 2. Auto-heal SIEM delivery: re-send any alerts that failed to reach the SIEM
    # (e.g. a transient outage or Elasticsearch still starting up), so no alert is
    # silently lost. Idempotent and safe to run often.
    scheduler.add_job(_auto_siem_replay, 'interval', minutes=10, id='siem_replay_job',
                      next_run_time=None)

    # Real-time Email Watcher now runs in a dedicated thread managed by main.py

    scheduler.start()
    logger.info("Background scheduler started successfully.")


def _auto_siem_replay():
    try:
        from framework.siem import replay_failed
        result = replay_failed(200)
        if result.get("replayed"):
            logger.info("Auto SIEM replay: re-sent %s failed alert(s).", result["replayed"])
    except Exception as e:
        logger.warning("Auto SIEM replay failed: %s", e)

def shutdown_scheduler():
    scheduler.shutdown()
