from flask import Blueprint

new_users = Blueprint('new_users', __name__)

from . import routes
