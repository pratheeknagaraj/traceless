from . import new_users
from flask import jsonify, request, abort
from flask import current_app as app
import os
from .. import traceless_crypto

@new_users.route('/')
def hello_world():
    # user_table = app.jinja_env.globals['server_user_table']
    # user_table["hello"] = 1
    return jsonify(server_user_table)

@new_users.route('/echo', methods=['POST'])
def echo():
    return jsonify(request.json)

@new_users.route('/server', methods=['POST'])
def server():
    n, e = app.jinja_env.globals['server_pk']
    return jsonify({'server_pk_n' : n, 'server_pk_e' : e})

@new_users.route('/subscribe', methods=['POST'])
def suscribe():
    user_table = app.jinja_env.globals['server_user_table']
    user_table_lock = app.jinja_env.globals['server_user_table_lock']
    with user_table_lock:
        server_usernames = app.jinja_env.globals['server_usernames']
        server_usernames_lock = app.jinja_env.globals['server_usernames_lock']
        with server_usernames_lock:
            if request.json['client_username'] in server_usernames:
                return server_usernames[request.json['client_username']]
            user = {
                'client_user_id' : len(user_table),
                'client_username' : request.json['client_username'],
                'client_pk_n' : request.json['client_pk_n'],
                'client_pk_e' : request.json['client_pk_e'],
                'client_sign_pk_n' : request.json['client_sign_pk_n'],
                'client_sign_pk_e' : request.json['client_sign_pk_e']
            }
            user_table.append(user)
            print "hello"
            server_usernames[request.json['client_username']] = jsonify({'user' : user,
                                                                        'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 201
            return server_usernames[request.json['client_username']]

@new_users.route('/update_user_table/', methods=['POST'])
def update_user_table():
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or not traceless_crypto.verify(request.json['nonce'], request.json['signature']):
            abort(400)
        
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]

        user_table = app.jinja_env.globals['server_user_table']
        user_table_lock = app.jinja_env.globals['server_user_table_lock']
        with user_table_lock:
            new_users = user_table[request.json['client_user_table_ptr']:]
            server_seen_nonces[request.json['nonce']] = jsonify({'new_users' : new_users, 
                                                                'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
            return server_seen_nonces[request.json['nonce']]
        
