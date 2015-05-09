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

    app.jinja_env.globals['server_me_url'] = 'http://localhost:9003'
    app.jinja_env.globals['server_master_url'] = 'http://localhost:5000'
    
    app.jinja_env.globals['server_view_number'] = 0
    
    app.jinja_env.globals['server_views'] = {} # in the form of {shard ranges : {'P' : ------, 'B' : ------ }}

    app.jinja_env.globals['shard'] = None
    
    app.jinja_env.globals['server_view_manager_lock'] = Lock()

    app.jinja_env.globals['server_messages_table'] = {}
    # app.jinja_env.globals['server_messages_table_lock'] = Lock()
    
    app.jinja_env.globals['server_seen_nonces'] = {}
    # app.jinja_env.globals['server_seen_nonces_lock'] = Lock()
    
    rsa = RSA.generate(2048)
    
    app.jinja_env.globals['server_rsa'] = rsa
    app.jinja_env.globals['server_pk'] = rsa.n, rsa.e  
    app.jinja_env.globals['server_sk'] = rsa.n, rsa.d

    from .pushes import pushes as pushes_blueprint
    app.register_blueprint(pushes_blueprint)

    from .pulls import pulls as pulls_blueprint
    app.register_blueprint(pulls_blueprint)

    from .view_manager import view_manager as view_manager_blueprint
    app.register_blueprint(view_manager_blueprint)

    from .async import async as async_blueprint
    app.register_blueprint(async_blueprint)

    return app

