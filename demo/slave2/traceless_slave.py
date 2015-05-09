#!/usr/bin/env python
import os
from app import create_app, celery
from flask.ext.script import Server, Manager

application = create_app(os.getenv('FLASK_CONFIG') or 'default')
manager = Manager(application)
manager.add_command("runserver", Server(port=9001))

if __name__ == '__main__':
    manager.run()
