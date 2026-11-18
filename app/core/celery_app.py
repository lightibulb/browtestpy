# Celery application shared by the web service and the worker.
from celery import Celery

from app.core.config import settings

celery = Celery(
    "anonymity_verifier",
    broker=settings.broker_url,
    backend=settings.result_backend,
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    result_expires=settings.scan_result_ttl,
    broker_connection_retry_on_startup=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_time_limit=300,
    task_soft_time_limit=240,
    worker_prefetch_multiplier=1,
)

# Import task modules explicitly so both web and worker register them.
# autodiscover_tasks(["app.tasks"]) looks for app.tasks.tasks and
# never imports app/tasks/orchestrator.py — worker would reject every
# scan with "unregistered task".
celery.conf.imports = (
    "app.tasks.layer1",
    "app.tasks.layer2",
    "app.tasks.orchestrator",
)
