from . import pushes
from flask import jsonify, current_app
import os
from .. import traceless_crypto

@pushes.route('/')
def hello_world():
    return "hello world"

@pushes.route('/reserve', methods=['POST'])
def reserve():
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or not verify(request.json['nonce'], request.json['signature']):
            abort(400)
        
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]
    
        server_reservation_table = app.jinja_env.globals['server_reservation_table']
        server_reservation_table_lock = app.jinja_env.globals['server_reservation_table_lock']
        with server_reservation_table_lock:
            if request.json['slot_id'] in server_reservation_table:
                server_seen_nonces[request.json['nonce']] = jsonify({'success' : False,
                                                                    'blinded_deletion_sign': None,
                                                                    'blinded_sign' : ust_sign(request.json['blinded_nonce'])}), 200
                return server_seen_nonces[request.json['nonce']]
            else:
                server_reservation_table[request.json['slot_id']] = 1
                server_seen_nonces[request.json['nonce']] = jsonify({'success' : True,
                                                                    'blinded_deletion_sign': ust_sign(request.json['blinded_deletion_nonce']),
                                                                    'blinded_sign' : ust_sign(request.json['blinded_nonce'])}), 200
                return server_seen_nonces[request.json['nonce']]
            

@pushes.route('/push', methods=['POST'])
def push():
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or not verify(request.json['nonce'], request.json['signature']):
            abort(400)
        
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]
        
        server_messages_table = app.jinja_env.globals['server_messages_table']
        server_messages_table_lock = app.jinja_env.globals['server_messages_table_lock']
        with server_messages_table_lock:
            if request.json['slot_id'] in server_messages_table:
                server_messages_table[request.json['slot_id']].append(request.json['message'])
            else:
                server_messages_table[request.json['slot_id']] = [request.json['message']]
            server_seen_nonces[request.json['nonce']] = jsonify({'blinded_sign' : ust_sign(request.json['blinded_nonce'])}), 200
            return server_seen_nonces[request.json['nonce']]
