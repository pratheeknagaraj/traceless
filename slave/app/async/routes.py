from app import celery
from flask import current_app as app
from datetime import timedelta
from celery.decorators import periodic_task
from flask import jsonify, request, abort
import requests
import json

@periodic_task(run_every=(timedelta(seconds=1)))
def ping():
    print "ping!"
    headers = {'content-type': 'application/json'}
    response = requests.post("http://localhost:9000" + "/send_ping", headers=headers, data=json.dumps({}))
    r = json.loads(response.text)
    if r['success'] is True:
    	print r['server_views'] 

