from . import view_manager
from flask import jsonify, request, abort
from flask import current_app as app
import os
from .. import traceless_crypto
import requests
import json

@view_manager.route('/', methods = ['POST'])
def hello_world():
    print "hello world"
    return "hello world"

@view_manager.route('/tick')
def tick():

@view_manager.route('/process_ping')
def process_ping():
