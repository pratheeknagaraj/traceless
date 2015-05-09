from . import new_conversations
from flask import jsonify, request, abort
from flask import current_app as app
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
        if not request.json or not traceless_crypto.verify(request.json['nonce'], request.json['signature']):
            print "GAVE ME A WRONG NONCE SIG PAIR"
            print request.json['nonce'], request.json['signature']
            abort(400)
        
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]
        
        server_new_conversations_table = app.jinja_env.globals['server_new_conversations_table']
        server_new_conversations_table_lock = app.jinja_env.globals['server_new_conversations_table_lock']
        with server_new_conversations_table_lock:
            server_new_conversations_table.append(request.json['message'])
            server_seen_nonces[request.json['nonce']] = jsonify({'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
            return server_seen_nonces[request.json['nonce']]

@new_conversations.route('/update_new_conversations_table', methods=['POST'])
def update_user_table():
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or not traceless_crypto.verify(request.json['nonce'], request.json['signature']):
            abort(400)
        
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]
     
        server_new_conversations_table = app.jinja_env.globals['server_new_conversations_table']
        server_new_conversations_table_lock = app.jinja_env.globals['server_new_conversations_table_lock']
        with server_new_conversations_table_lock:
            new_conversations = server_new_conversations_table[request.json['client_new_conversations_table_ptr']:]
            server_seen_nonces[request.json['nonce']] = jsonify({'new_conversations' : new_conversations,
                                                                'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
            return server_seen_nonces[request.json['nonce']]



