from flask import Blueprint

pushes = Blueprint('pushes', __name__)

from . import routes
