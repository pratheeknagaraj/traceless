from master_app import celery
from flask import current_app as app
from datetime import timedelta
from celery.decorators import periodic_task
import requests 
import json

@periodic_task(run_every=(timedelta(seconds=1)))
def tick():
    print "ticking!"
    headers = {'content-type': 'application/json'}
    response = requests.post("http://localhost:5000" + "/tick", headers=headers, data=json.dumps({}))
    r = json.loads(response.text)
    print r['views']
