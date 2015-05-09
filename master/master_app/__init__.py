from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from config import config
from threading import Lock
from Crypto.PublicKey import RSA
from celery import Celery

db = SQLAlchemy()
celery = Celery()

def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    db.init_app(app)
    celery.config_from_object(app.config)
    
    app.jinja_env.globals['server_me_url'] = 'http://localhost:5000'    

    app.jinja_env.globals['server_user_table'] = []
    app.jinja_env.globals['server_user_table_lock'] = Lock()
    
    app.jinja_env.globals['server_usernames'] = {}
    app.jinja_env.globals['server_usernames_lock'] = Lock()
    
    app.jinja_env.globals['server_new_conversations_table'] = []
    app.jinja_env.globals['server_new_conversations_table_lock'] = Lock()
    
    app.jinja_env.globals['server_seen_nonces'] = {}
    app.jinja_env.globals['server_seen_nonces_lock'] = Lock()
    
    rsa = RSA.generate(2048)

    app.jinja_env.globals['server_view_manager_lock'] = Lock()
    
    app.jinja_env.globals['server_rsa'] = rsa
    app.jinja_env.globals['server_pk'] = rsa.n, rsa.e  
    app.jinja_env.globals['server_sk'] = rsa.n, rsa.d
    
    app.jinja_env.globals['num_shards_init'] = 1
    app.jinja_env.globals['num_slaves_init'] = 2 * app.jinja_env.globals['num_shards_init']
    app.jinja_env.globals['slave_keys'] = {} # In the form {url : {n : ---, d: ---, e : ---}}

    app.jinja_env.globals['server_views'] = {} # in the form of {shard range : {'N' : ------, 'P' : ------, 'B' : ------ }}

    app.jinja_env.globals['primary_acks'] = {} # int the form {shard_range : view_num}
    app.jinja_env.globals['backup_acks'] = {} # int the form {shard_range : view_num}
    
    app.jinja_env.globals['current_tick'] = 0
    app.jinja_env.globals['primary_ticks'] = {}
    app.jinja_env.globals['backup_ticks'] = {}
    
    total_range = 2**128
    base_val = total_range/app.jinja_env.globals['num_shards_init']
    for i in xrange(app.jinja_env.globals['num_shards_init']):
        shard = str((base_val * i, base_val * (i+1)))
        app.jinja_env.globals['server_views'][shard] = {'N' : 0, 'P' : '', 'B' : ''}        
        app.jinja_env.globals['primary_acks'][shard] = 0
        app.jinja_env.globals['primary_ticks'][shard] = 0
        app.jinja_env.globals['backup_ticks'][shard] = 0     
    
    from .new_conversations import new_conversations as new_conversations_blueprint
    app.register_blueprint(new_conversations_blueprint)

    from .new_users import new_users as new_users_blueprint
    app.register_blueprint(new_users_blueprint)
    
    from .view_manager import view_manager as view_manager_blueprint
    app.register_blueprint(view_manager_blueprint)

    from .async import async as async_blueprint
    app.register_blueprint(async_blueprint)

    return app

