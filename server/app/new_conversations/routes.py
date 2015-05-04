from . import new_conversations
from flask import jsonify, current_app
import os
from .. import traceless_crypto

@new_conversations.route('/')
def hello_world():
    return "hello world"

@new_conversations.route('/initiate', methods=['POST'])
def initiate():
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or not verify(request.json['nonce'], request.json['signature']):
            abort(400)
        
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]
        
        server_new_conversations_table = app.jinja_env.globals['server_new_conversations_table']
        server_new_conversations_table_lock = app.jinja_env.globals['server_new_conversations_table_lock']
        with server_new_conversations_table_lock:
            server_new_conversations_table.append(request.json['message'])
            server_seen_nonces[request.json['nonce']] = jsonify({'blinded_sign' : ust_sign(request.json['blinded_nonce'])}), 200
            return server_seen_nonces[request.json['nonce']]

@new_conversations.route('/update_new_conversations_table/<int:client_new_conversations_table_ptr>', methods=['POST'])
def update_user_table(client_new_conversations_table_ptr):
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or not verify(request.json['nonce'], request.json['signature']):
            abort(400)
        
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]
     
        server_new_conversations_table = app.jinja_env.globals['server_new_conversations_table']
        server_new_conversations_table_lock = app.jinja_env.globals['server_new_conversations_table_lock']
        with server_new_conversations_table_lock:
            new_conversations = sever_new_conversations_table[client_new_conversations_table_ptr:]
            server_seen_nonces[request.json['nonce']] = jsonify({'new_conversations' : new_conversations,
                                                                'blinded_sign' : ust_sign(request.json['blinded_nonce'])}), 200
            return server_seen_nonces[request.json['nonce']]



