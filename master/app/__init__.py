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
    
    app.jinja_env.globals['server_me_url'] = None    

    app.jinja_env.globals['server_user_table'] = []
    app.jinja_env.globals['server_user_table_lock'] = Lock()
    
    app.jinja_env.globals['server_usernames'] = {}
    app.jinja_env.globals['server_usernames_lock'] = Lock()
    
    app.jinja_env.globals['server_new_conversations_table'] = []
    app.jinja_env.globals['server_new_conversations_table_lock'] = Lock()
    
    app.jinja_env.globals['server_seen_nonces'] = {}
    app.jinja_env.globals['server_seen_nonces_lock'] = Lock()
    
    rsa = RSA.generate(2048)
    
    app.jinja_env.globals['server_rsa'] = rsa
    app.jinja_env.globals['server_pk'] = rsa.n, rsa.e  
    app.jinja_env.globals['server_sk'] = rsa.n, rsa.d
    
    app.jinja_env.globals['slave_urls'] = []
    app.jinja_env.globals['slave_keys'] = {} # In the form {url : {n : ---, d: ---, e : ---}}
    
    app.jinja_env.globals['server_view_number'] = 0

    app.jinja_env.globals['server_views'] = {} # in the form of {shard ranges : {'P' : ------, 'B' : ------ }}

    app.jinja_env.globals['shard_ranges'] = [] # We are splitting int shards of size 4, and its inclusive, exclusive
    
    from .new_conversations import new_conversations as new_conversations_blueprint
    app.register_blueprint(new_conversations_blueprint)

    from .new_users import new_users as new_users_blueprint
    app.register_blueprint(new_users_blueprint)
    
    from .view_manager import view_manager as view_manager_blueprint
    app.register_blueprint(view_manager_blueprint)

    from .async import async as async_blueprint
    app.register_blueprint(async_blueprint)

    return app

