from . import new_users
from flask import jsonify, current_app
import os
from .. import traceless_crypto

@new_users.route('/')
def hello_world():
    # user_table = current_app.jinja_env.globals['server_user_table']
    # user_table["hello"] = 1
    return jsonify(server_user_table)

@new_users.route('/suscribe', methods=['POST'])
def suscribe():
    user_table = current_app.jinja_env.globals['server_user_table']
    user_table_lock = current_app.jinja_env.globals['server_user_table_lock']
    with user_table_lock:
        client_user_id = long(binascii.hexlify(os.urandom(32)), 16)
        user = {
            'client_user_id' : len(user_table)
            'client_username' : request.json['client_username']
            'client_pk' : request.json['client_pk']
            'client_sign_pk' : request.json['client_sign_pk']
        }
        user_table.append(user)
        return jsonify({'user' : user, 
                        'blinded_sign' : ust_sign(request.json['blinded_nonce']), 
                        'server_pk' : app.jinja_env.globals['server_pk']}), 201

@new_users.route('/update_user_table/<int:client_user_table_ptr>', methods=['POST'])
def update_user_table(client_user_table_ptr):
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or request.json['nonce'] in server_seen_nonces or not verify(request.json['nonce'], request.json['signature']):
            abort(400)
        else:
            server_seen_nonces[request.json['nonce']] = 1

    user_table = current_app.jinja_env.globals['server_user_table']
    user_table_lock = current_app.jinja_env.globals['server_user_table_lock']
    with user_table_lock:
        new_users = user_table[client_user_table_ptr:]
        return jsonify({'new_users' : new_users, 
                        'blinded_sign' : ust_sign(request.json['blinded_nonce'])}), 200
        
