from . import pushes
from flask import jsonify, request, abort
from flask import current_app as app
import os
from .. import traceless_crypto
from ast import literal_eval
import requests
import json

# @pushes.route('/reserve', methods=['POST'])
# def reserve():
#     server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
#     server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
#     with server_seen_nonces_lock:
#         if not request.json or not traceless_crypto.verify(request.json['nonce'], request.json['signature']):
#             abort(400)
        
#         if request.json['nonce'] in server_seen_nonces:
#             return server_seen_nonces[request.json['nonce']]
    
#         server_reservation_table = app.jinja_env.globals['server_reservation_table']
#         server_reservation_table_lock = app.jinja_env.globals['server_reservation_table_lock']
#         with server_reservation_table_lock:
#             if request.json['slot_id'] in server_reservation_table:
#                 server_seen_nonces[request.json['nonce']] = jsonify({'success' : False,
#                                                                     'blinded_deletion_sign': None,
#                                                                     'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
#                 return server_seen_nonces[request.json['nonce']]
#             else:
#                 server_reservation_table[request.json['slot_id']] = 1
#                 server_seen_nonces[request.json['nonce']] = jsonify({'success' : True,
#                                                                     'blinded_deletion_sign': traceless_crypto.ust_sign(request.json['blinded_deletion_nonce']),
#                                                                     'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
#                 return server_seen_nonces[request.json['nonce']]
            

@pushes.route('/push', methods=['POST'])
def push():
    with app.jinja_env.globals['server_view_manager_lock']:
        server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
        if not request.json or not traceless_crypto.verify(request.json['nonce'], request.json['signature']):
            abort(400)
        
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]
        
        shard = app.jinja_env.globals['shard']
        srange = literal_eval(app.jinja_env.globals['shard'])
        if request.json['slot_id'] < srange[0] or  request.json['slot_id'] >= srange[1] \
                or app.jinja_env.globals['server_views'][shard]['P'] != app.jinja_env.globals['server_me_url']:
            server_seen_nonces[request.json['nonce']] = jsonify({'success' : False,
                                                                'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
            return server_seen_nonces[request.json['nonce']]

        server_messages_table = app.jinja_env.globals['server_messages_table']

        
        if request.json['slot_id'] in server_messages_table:
            if app.jinja_env.globals['server_views'][shard]['B'] != '':
                try:
                    args = {
                        'messages_table' :  {request.json['slot_id'] : server_messages_table[request.json['slot_id']] + [request.json['message']]}
                    }
                    headers = {'content-type': 'application/json'}
                    response = requests.post(app.jinja_env.globals['server_views'][shard]['B'] + "/process_forward", headers=headers, data=json.dumps(args))
                    r = json.loads(response.text)
                    if r['success'] == False:
                        server_seen_nonces[request.json['nonce']] = jsonify({'success' : False,
                                                                            'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
                        return server_seen_nonces[request.json['nonce']]
                except requests.exceptions.RequestException as e:
                    server_seen_nonces[request.json['nonce']] = jsonify({'success' : False,
                                                                        'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
                    return server_seen_nonces[request.json['nonce']]
            server_messages_table[request.json['slot_id']].append(request.json['message'])
        else:
            if app.jinja_env.globals['server_views'][shard]['B'] != '':
                try:
                    args = {
                        'messages_table' : {request.json['slot_id'] : [request.json['message']]}
                    }
                    headers = {'content-type': 'application/json'}
                    response = requests.post(app.jinja_env.globals['server_views'][shard]['B'] + "/process_forward", headers=headers, data=json.dumps(args))
                    r = json.loads(response.text)
                    if r['success'] == False:
                        server_seen_nonces[request.json['nonce']] = jsonify({'success' : False,
                                                                            'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
                        return server_seen_nonces[request.json['nonce']]
                except requests.exceptions.RequestException as e:
                    server_seen_nonces[request.json['nonce']] = jsonify({'success' : False,
                                                                        'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
                    return server_seen_nonces[request.json['nonce']]
            server_messages_table[request.json['slot_id']] = [request.json['message']]
        
        server_seen_nonces[request.json['nonce']] = jsonify({'success' : True,
                                                            'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
        print server_messages_table
        return server_seen_nonces[request.json['nonce']]
