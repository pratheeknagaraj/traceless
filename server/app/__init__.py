from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from config import config
from threading import Lock

db = SQLAlchemy()

def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    db.init_app(app)

    app.jinja_env.globals['seen_commands'] = {}
    
    app.jinja_env.globals['server_user_table'] = []
    app.jinja_env.globals['server_user_table_lock'] = Lock()
    
    app.jinja_env.globals['server_new_conversations_table'] = []
    app.jinja_env.globals['server_new_conversations_table_lock'] = Lock()
    
    app.jinja_env.globals['server_messages_table'] = {}
    app.jinja_env.globals['server_messages_table_lock'] = Lock()
    
    app.jinja_env.globals['server_seen_nonces'] = {}
    app.jinja_env.globals['server_seen_nonces_lock'] = Lock()
    
    app.jinja_env.globals['server_deletion_nonces'] = {}
    app.jinja_env.globals['server_deletion_nonces_lock'] = Lock()

    app.jinja_env.globals['server_reservation_table'] = {}
    app.jinja_env.globals['server_reservation_table_lock'] = Lock()
    
    app.jinja_env.globals['server_current_block_range'] = (1, 1000000)
    # app.jinja_env.globals['server_pk'] =  
    # app.jinja_env.globals['server_sk'] =  

    from .pushes import pushes as pushes_blueprint
    app.register_blueprint(pushes_blueprint, url_prefix='/push')

    from .pulls import pulls as pulls_blueprint
    app.register_blueprint(pulls_blueprint, url_prefix='/pull')

    from .new_conversations import new_conversations as new_conversations_blueprint
    app.register_blueprint(new_conversations_blueprint, url_prefix='/new_conversation')

    from .new_users import new_users as new_users_blueprint
    app.register_blueprint(new_users_blueprint, url_prefix='/new_user')

    return app

