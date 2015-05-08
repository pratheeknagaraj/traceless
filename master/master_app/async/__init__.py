from flask import Blueprint

async = Blueprint('async', __name__)

from . import routes
