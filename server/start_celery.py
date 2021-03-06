from app import celery
from traceless_server import application 

if __name__ == '__main__':
    with application.app_context():
        celery.start()
