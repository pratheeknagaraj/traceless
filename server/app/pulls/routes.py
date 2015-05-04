from . import pulls
from flask import jsonify, request, abort
from flask import current_app as app
import os
from .. import traceless_crypto

@pulls.route('/')
def hello_world():
    return "hello world"

@pulls.route('/pull', methods=['POST'])
def pull():
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
            server_seen_nonces[request.json['nonce']] = jsonify({'messages' : server_messages_table[request.json['slot_id']],
                                                                'blinded_sign' : ust_sign(request.json['blinded_nonce'])}), 200
            return server_seen_nonces[request.json['nonce']]

@pulls.route('/delete', methods=['POST'])
def delete():
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or not verify(request.json['nonce'], request.json['signature']):
            abort(400)
        
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]
    
        server_deletion_nonces = app.jinja_env.globals['server_deletion_nonces']
        server_deletion_nonces_lock = app.jinja_env.globals['server_deletion_nonces_lock']
        with server_deletion_nonces_lock:
            if request.json['deletion_nonce'] in server_deletion_nonces or not deletion_verify(request.json['deletion_nonce'], request.json['deletion_signature'], request.json['slot_id']):
                abort(400)
            else:
                server_deletion_nonces[request.json['deletion_nonce']] = 1
        
        server_reservation_table = app.jinja_env.globals['server_reservation_table']
        server_reservation_table_lock = app.jinja_env.globals['server_reservation_table_lock']
    
        server_messages_table = app.jinja_env.globals['server_messages_table']
        server_messages_table_lock = app.jinja_env.globals['server_messages_table_lock']

        with server_reservation_table_lock:
            with server_messages_table_lock:
                server_reservation_table.pop(request.json['slot_id'], None)
                server_messages_table.pop(request.json['slot_id'], None)
                server_seen_nonces[request.json['nonce']] = jsonify({'blinded_sign' : ust_sign(request.json['blinded_nonce'])}), 200
                return server_seen_nonces[request.json['nonce']]



