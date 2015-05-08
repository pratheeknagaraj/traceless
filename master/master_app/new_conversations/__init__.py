from flask import Blueprint

new_conversations = Blueprint('new_conversations', __name__)

from . import routes
