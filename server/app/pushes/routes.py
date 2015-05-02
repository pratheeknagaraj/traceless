from . import pushes
from flask import jsonify, current_app
import os
from .. import traceless_crypto

@pushes.route('/')
def hello_world():
    return "hello world"

@new_users.route('/reserve>', methods=['POST'])
def reserve():
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or request.json['nonce'] in server_seen_nonces or not verify(request.json['nonce'], request.json['signature']):
            abort(400)
        else:
            server_seen_nonces[request.json['nonce']] = 1
    
    server_reservation_table = app.jinja_env.globals['server_reservation_table']
    server_reservation_table_lock = app.jinja_env.globals['server_reservation_table_lock']
    with server_reservation_table_lock:
        if request.json['block_write'] in server_reservation_table:
            return jsonify({'success' : False,
                            'blinded_deletion_sign': None,
                            'blinded_sign' : ust_sign(request.json['blinded_nonce'])}), 200
        else:
            server_reservation_table[request.json['block_write']] = 1
            return jsonify({'success' : True,
                            'blinded_deletion_sign': ust_sign(request.json['blinded_deletion_nonce'])
                            'blinded_sign' : ust_sign(request.json['blinded_nonce'])}), 200
            

@new_users.route('/push>', methods=['POST'])
def push():
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or request.json['nonce'] in server_seen_nonces or not verify(request.json['nonce'], request.json['signature']):
            abort(400)
        else:
            server_seen_nonces[request.json['nonce']] = 1
    
    server_messages_table = app.jinja_env.globals['server_messages_table']
    server_messages_table_lock = app.jinja_env.globals['server_messages_table_lock']
    with server_messages_table_lock:
        server_messages_table[request.json['block_write']] = request.json['message']
        return jsonify({'blinded_sign' : ust_sign(request.json['blinded_nonce'])}), 200
