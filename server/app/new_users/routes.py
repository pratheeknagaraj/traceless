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
        server_usernames = app.jinja_env.globals['server_usernames']
        server_usernames_lock = app.jinja_env.globals['server_usernames_lock']
        with server_usernames_lock:
            if request.json['client_username'] in server_usernames:
                return server_usernames[request.json['client_username']]
            user = {
                'client_user_id' : len(user_table)
                'client_username' : request.json['client_username']
                'client_pk' : request.json['client_pk']
                'client_sign_pk' : request.json['client_sign_pk']
            }
            user_table.append(user)
            server_usernames[request.json['client_username']] = jsonify({'user' : user,
                                                                        'blinded_sign' : ust_sign(request.json['blinded_nonce']),
                                                                        'server_pk' : app.jinja_env.globals['server_pk']}), 201
            return server_usernames[request.json['client_username']]

@new_users.route('/update_user_table/<int:client_user_table_ptr>', methods=['POST'])
def update_user_table(client_user_table_ptr):
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or not verify(request.json['nonce'], request.json['signature']):
            abort(400)
        
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]

        user_table = current_app.jinja_env.globals['server_user_table']
        user_table_lock = current_app.jinja_env.globals['server_user_table_lock']
        with user_table_lock:
            new_users = user_table[client_user_table_ptr:]
            server_seen_nonces[request.json['nonce']] = jsonify({'new_users' : new_users, 
                                                                'blinded_sign' : ust_sign(request.json['blinded_nonce'])}), 200
            return server_seen_nonces[request.json['nonce']]
        
