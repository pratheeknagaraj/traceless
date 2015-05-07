from app import celery
from flask import current_app as app
from datetime import timedelta
from celery.decorators import periodic_task

@periodic_task(run_every=(timedelta(microseconds=100)))
def tick():
    headers = {'content-type': 'application/json'}
    response = requests.post("http://localhost:5000" + "/tick", headers=headers, data=json.dumps({}))

