from flask import Blueprint

view_manager = Blueprint('view_manager', __name__)

from . import routes
