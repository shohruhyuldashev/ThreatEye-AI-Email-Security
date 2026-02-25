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

    # Real-time Email Watcher now runs in a dedicated thread managed by main.py

    scheduler.start()
    logger.info("Background scheduler started successfully.")

def shutdown_scheduler():
    scheduler.shutdown()
