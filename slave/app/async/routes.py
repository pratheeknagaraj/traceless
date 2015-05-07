from app import celery
from flask import current_app as app
from datetime import timedelta
from celery.decorators import periodic_task
from flask import jsonify, request, abort
import requests
import json

@periodic_task(run_every=(timedelta(microseconds=100)))
def ping():
    headers = {'content-type': 'application/json'}
    response = requests.post("http://localhost:5000" + "/send_ping", headers=headers, data=json.dumps({}))
    
