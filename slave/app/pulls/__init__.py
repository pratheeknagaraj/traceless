from flask import Blueprint

pulls = Blueprint('pulls', __name__)

from . import routes
