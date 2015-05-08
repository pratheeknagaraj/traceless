from . import view_manager
from flask import jsonify, request, abort
from flask import current_app as app
import os
from .. import traceless_crypto
import requests
import json

@view_manager.route('/', methods = ['POST'])
def hello_world():
    print "hello world"
    return "hello world"

@view_manager.route('/tick', methods=['POST'])
def tick():
    with app.jinja_env.globals['server_view_manager_lock']:
        app.jinja_env.globals['current_tick'] += 1
        for shard in app.jinja_env.globals['server_views']:
            if app.jinja_env.globals['current_tick'] - app.jinja_env.globals['primary_ticks'][shard] >= 5 \
                    and app.jinja_env.globals['server_views'][shard]['N'] == app.jinja_env.globals['primary_acks'][shard] \
                    and app.jinja_env.globals['server_views'][shard]['B'] != '':
                app.jinja_env.globals['server_views'][shard]['P'] = app.jinja_env.globals['server_views'][shard]['B']
                app.jinja_env.globals['server_views'][shard]['B'] = ''
                app.jinja_env.globals['server_views'][shard]['N'] += 1
                app.jinja_env.globals['primary_acks'][shard] = app.jinja_env.globals['backup_acks'][shard]
                app.jinja_env.globals['primary_ticks'][shard] = app.jinja_env.globals['backup_ticks'][shard] 
            if app.jinja_env.globals['server_views'][shard]['B'] != '' \
                    and app.jinja_env.globals['current_tick'] - app.jinja_env.globals['backup_ticks'][shard] >= 5 \
                    and app.jinja_env.globals['server_views'][shard]['N'] == app.jinja_env.globals['primary_acks'][shard]:
                app.jinja_env.globals['server_views'][shard]['B'] = ''
                app.jinja_env.globals['server_views'][shard]['N'] += 1
    return jsonify({'views' : app.jinja_env.globals['server_views']}), 200
        

@view_manager.route('/process_ping', methods=['POST'])
def process_ping():
    with app.jinja_env.globals['server_view_manager_lock']:
        app.jinja_env.globals['slave_keys'][request.json['slave_url']] = {'n' : request.json['rsa_n'], 'd' : request.json['rsa_d'], 'e' : request.json['rsa_d']}
        if is_registered(request.json['slave_url']) is None:
            no_primary = shards_without_primary()
            no_backup = shards_without_backup()
            if len(no_primary) != 0:
                for shard in no_primary:
                    if app.jinja_env.globals['server_views'][shard]['N'] == 0:
                        app.jinja_env.globals['server_views'][shard]['N'] = request.json['view_num'] + 1
                        app.jinja_env.globals['server_views'][shard]['P'] = request.json['slave_url']
                        app.jinja_env.globals['primary_ticks'][shard] = app.jinja_env.globals['current_tick']
                        break
            elif len(no_backup) != 0:
                for shard in no_backup:
                    if app.jinja_env.globals['server_views'][shard]['N'] == app.jinja_env.globals['primary_acks'][shard]:
                        app.jinja_env.globals['server_views'][shard]['N'] += 1
                        app.jinja_env.globals['server_views'][shard]['B'] = request.json['slave_url']
                        app.jinja_env.globals['backup_ticks'][shard] = app.jinja_env.globals['current_tick']
                        break
        else:
            shard, view = is_registered(request.json['slave_url'])
            if view['P'] == request.json['slave_url']:
                if request.json['view_num'] == 0 and view['B'] != '':
                    app.jinja_env.globals['server_views'][shard]['P'] = app.jinja_env.globals['server_views'][shard]['B']
                    app.jinja_env.globals['server_views'][shard]['B'] = ''
                    app.jinja_env.globals['server_views'][shard]['N'] += 1
                    app.jinja_env.globals['primary_acks'][shard] = app.jinja_env.globals['backup_acks'][shard]
                    app.jinja_env.globals['primary_ticks'][shard] = app.jinja_env.globals['backup_ticks'][shard]
                else:
                    app.jinja_env.globals['primary_acks'][shard] = request.json['view_num']
                    app.jinja_env.globals['primary_ticks'][shard] = app.jinja_env.globals['current_tick']
            elif view['B'] == request.json['slave_url']:
                if request.json['view_num'] == 0 and app.jinja_env.globals['server_views'][shard]['N'] == app.jinja_env.globals['primary_acks'][shard]:
                    app.jinja_env.globals['server_views'][shard]['N'] += 1
                    app.jinja_env.globals['backup_ticks'][shard] = app.jinja_env.globals['current_tick']
                elif request.json['view_num'] != 0:
                    app.jinja_env.globals['backup_ticks'][shard] = app.jinja_env.globals['current_tick']
         
    return jsonify({'views' : app.jinja_env.globals['server_views']}), 200


@view_manager.route('/update_server_view', methods=['POST']):
def update_server_view():
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or not traceless_crypto.verify(request.json['nonce'], request.json['signature']):
            abort(400)
        
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]

        shards = {}

        with app.jinja_env.globals['server_view_manager_lock']:
            for shard in app.jinja_env.globals['server_views']:
                if app.jinja_env.globals['server_views'][shard]['P'] == '':
                    shard[shard] = None
                else:
                    shards[shard] = {
                        'url'  :  app.jinja_env.globals['server_views'][shard]['P'],
                        'n'    :  app.jinja_env.globals['slave_keys'][app.jinja_env.globals['server_views'][shard]]['n']
                        'd'    :  app.jinja_env.globals['slave_keys'][app.jinja_env.globals['server_views'][shard]]['d']
                    }
            server_seen_nonces[request.json['nonce']] = jsonify({'shards' : shards
                                                                'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200
            return server_seen_nonces[request.json['nonce']]

@view_manager.route('/connect_to_slave', methods=['POST']):
    server_seen_nonces = app.jinja_env.globals['server_seen_nonces']
    server_seen_nonces_lock = app.jinja_env.globals['server_seen_nonces_lock']
    with server_seen_nonces_lock:
        if not request.json or not traceless_crypto.verify(request.json['nonce'], request.json['signature']):
            abort(400)
        
        if request.json['nonce'] in server_seen_nonces:
            return server_seen_nonces[request.json['nonce']]
        slave_n = app.jinja_env.globals['slave_keys'][request.json['slave_url']]['n']
        slave_d = app.jinja_env.globals['slave_keys'][request.json['slave_url']]['d'] 
        server_seen_nonces[request.json['nonce']] = jsonify({'blind_slave_sign' : master_ust_sign_for_slave(request.json['blinded_slave_nonce'], slave_n, slave_d), 
                                                            'blinded_sign' : traceless_crypto.ust_sign(request.json['blinded_nonce'])}), 200


                 
                
def is_registered(slave_url):
    views = app.jinja_env.globals['server_views']
    shard = [x for x in views if views[x]['P'] == slave_url or views[x]['B'] == slave_url]
    if len(shard) == 0:
        return None
    else:
        shard = shard[0]
        return shard, views[shard]

def shards_without_primary():
    views = app.jinja_env.globals['server_views']
    return [x for x in views if views[x]['P'] == '']

def shards_without_backup():
    views = app.jinja_env.globals['server_views']
    return [x for x in views if views[x]['B'] == '']


