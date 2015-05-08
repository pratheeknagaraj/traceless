from . import pulls
from flask import jsonify, request, abort
from flask import current_app as app
import os
from .. import traceless_crypto

@pulls.route('/pull', methods=['POST'])
def pull():
    with app.jinja_env.globals['server_view_manager_lock']:
        server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
        
        if not request.json or not traceless_crypto.verify(request.json['nonce'], request.json['signature']):
            abort(400)
    
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]

        shard = literal_eval(app.jinja_env.globals['shard'])
        if request.json['slot_id'] < shard[0] or  request.json['slot_id'] >= shard[1] \
                or app.jinja_env.globals['server_views'][shard]['P'] != app.jinja_env.globals['server_me_url']
            server_seen_nonces[request.json['nonce']] = jsonify({'success' : False,
                                                                'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
            return server_seen_nonces[request.json['nonce']]

        if app.jinja_env.globals['server_views'][shard]['B'] != '':
            try:
                args = {
                    'messages_table' :  {}
                }
                response = requests.post(app.jinja_env.globals['server_master_url'] + "/process_forward", headers=headers, data=json.dumps(args))
                r = json.loads(response.text)
                if r['success'] == False:
                    server_seen_nonces[request.json['nonce']] = jsonify({'success' : False,
                                                                        'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
                    return server_seen_nonces[request.json['nonce']]
            except requests.exceptions.RequestException as e:
                server_seen_nonces[request.json['nonce']] = jsonify({'success' : False,
                                                                    'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
                return server_seen_nonces[request.json['nonce']]
            
        server_messages_table = app.jinja_env.globals['server_messages_table']
        if request.json['slot_id'] in server_messages_table:             
            server_seen_nonces[request.json['nonce']] = jsonify({'messages' : server_messages_table[request.json['slot_id']],
                                                                'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
        else:
            server_seen_nonces[request.json['nonce']] = jsonify({'messages' : [],
                                                                'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
        return server_seen_nonces[request.json['nonce']]

# @pulls.route('/delete', methods=['POST'])
# def delete():
#     server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
#     server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
#     with server_seen_nonces_lock:
#         if not request.json or not traceless_crypto.verify(request.json['nonce'], request.json['signature']):
#             abort(400)
        
#         if request.json['nonce'] in server_seen_nonces:
#             return server_seen_nonces[request.json['nonce']]
    
#         server_deletion_nonces = app.jinja_env.globals['server_deletion_nonces']
#         server_deletion_nonces_lock = app.jinja_env.globals['server_deletion_nonces_lock']
#         with server_deletion_nonces_lock:
#             if request.json['deletion_nonce'] in server_deletion_nonces or not traceless_crypto.deletion_verify(request.json['deletion_nonce'], request.json['deletion_signature'], request.json['slot_id']):
#                 abort(400)
#             else:
#                 server_deletion_nonces[request.json['deletion_nonce']] = 1
        
#         server_reservation_table = app.jinja_env.globals['server_reservation_table']
#         server_reservation_table_lock = app.jinja_env.globals['server_reservation_table_lock']
    
#         server_messages_table = app.jinja_env.globals['server_messages_table']
#         server_messages_table_lock = app.jinja_env.globals['server_messages_table_lock']

#         with server_reservation_table_lock:
#             with server_messages_table_lock:
#                 server_reservation_table.pop(request.json['slot_id'], None)
#                 server_messages_table.pop(request.json['slot_id'], None)
#                 server_seen_nonces[request.json['nonce']] = jsonify({'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
#                 return server_seen_nonces[request.json['nonce']]



