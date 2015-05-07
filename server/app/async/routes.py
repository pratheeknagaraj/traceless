from app import celery
from flask import current_app as app
from datetime import timedelta
from celery.decorators import periodic_task

@periodic_task(run_every=(timedelta(seconds=3)))
def email_example():
    print app.jinja_env.globals['server_user_table']
