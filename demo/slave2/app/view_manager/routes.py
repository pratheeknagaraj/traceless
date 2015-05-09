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

@view_manager.route('/send_ping', methods=['POST'])
def send_ping():
    with app.jinja_env.globals['server_view_manager_lock']:
        try:
            headers = {'content-type': 'application/json'}
            args = {
                'slave_url' :  app.jinja_env.globals['server_me_url'],
                'view_num'  :  app.jinja_env.globals['server_view_number'],
                'rsa_n'     :  app.jinja_env.globals['server_rsa'].n,
                'rsa_d'     :  app.jinja_env.globals['server_rsa'].d,
                'rsa_e'     :  app.jinja_env.globals['server_rsa'].e
            }
            response = requests.post(app.jinja_env.globals['server_master_url'] + "/process_ping", headers=headers, data=json.dumps(args))
            r = json.loads(response.text)
            shard = get_shard(r['views'])
            if shard is not None:
                if shard in app.jinja_env.globals['server_views']:
                    print app.jinja_env.globals['server_views']
                    needForward = r['views'][shard]['B'] != '' \
                        and r['views'][shard]['P'] == app.jinja_env.globals['server_me_url'] \
                        and r['views'][shard]['B'] != app.jinja_env.globals['server_views'][shard]['B'] 
                    if needForward:
                        try:
                            finished = False
                            while not finished:
                                # print "TRYING TO FORWARD!"
                                args = {
                                    'messages_table' : app.jinja_env.globals['server_messages_table'] 
                                }
                                headers = {'content-type': 'application/json'}
                                response = requests.post(r['views'][shard]['B'] + "/process_forward", headers=headers, data=json.dumps(args))
                                r2 = json.loads(response.text)
                                finished = r2['success']
                                # if r2['success'] == False:
                                #     return jsonify({'success' : False}), 200
                        except requests.exceptions.RequestException as e:
                            print e
                            return jsonify({'success' : False}), 200
                app.jinja_env.globals['shard'] = shard
                app.jinja_env.globals['server_view_number'] = r['views'][app.jinja_env.globals['shard']]['N']
                app.jinja_env.globals['server_views'] = r['views']
            
            return jsonify({'success' : True,
                            'server_views' : r['views']}), 200 
             
        except requests.exceptions.RequestException as e:
            print e
            return jsonify({'success' : False}), 200

@view_manager.route('/process_forward', methods=['POST'])
def process_forward():
    with app.jinja_env.globals['server_view_manager_lock']:
        if app.jinja_env.globals['server_views'][app.jinja_env.globals['shard']]['B'] != app.jinja_env.globals['server_me_url']:
            return jsonify({'success' : False}), 200
        for slot in request.json['messages_table']:
            app.jinja_env.globals['server_messages_table'][slot] = request.json['messages_table'][slot]
        print app.jinja_env.globals['server_messages_table']
        return jsonify({'success' : True}), 200
    
def get_shard(views):
    shard = [x for x in views if views[x]['P'] == app.jinja_env.globals['server_me_url'] or views[x]['B'] == app.jinja_env.globals['server_me_url']]
    if len(shard) == 0:
        return None
    else:
        shard = shard[0]
        return shard
