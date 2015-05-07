from . import view_manager
from flask import jsonify, request, abort
from flask import current_app as app
import os
from .. import traceless_crypto
import requests
import json

@view_manager.route('/', methods = ['POST'])
def hello_world():
    print "hello world"
    return "hello world"

@view_manager.route('/send_ping')
def send_ping(): 
    try:
        headers = {'content-type': 'application/json'}
        args = {
            "me"           :  app.jinja_env.globals['server_me_url']
            "view_number"  :  app.jinja_env.globals['server_view_number']
        }
        response = requests.post(app.jinja_env.globals['server_master_url'] + "/process_ping", headers=headers, data=json.dumps(args))
        r = json.loads(response.text)
        app.jinja_env.globals['server_view_number'] = r["server_view_number"]
        app.jinja_env.globals['server_views'] = r["server_views"]
        return jsonify({'success' : True}), 200 
    
    except requests.exceptions.RequestException as e:
        print e
        return jsonify({'success' : False}), 200
    
