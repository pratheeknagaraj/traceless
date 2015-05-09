# Traceless Distributed Demo

## Prequisites

First, we need to complete generic setup for the project.
    
    # GENERAL SETUP 
    # install mysql and swig
    brew install mysql
    brew install rabbitmq

    # create mysql database
    mysql -u root
    create database traceless_db;
    exit;

    # Setup rabbitmq for celery
    # NOTE: THIS IS CRITICAL - separate vhosts enable multiple celery processes to
    # run independently on a single computer
    rabbitmqctl add_user master_user master_password
    rabbitmqctl add_vhost master_host
    rabbitmqctl set_permissions -p master_host master_user ".*" ".*" ".*"

    rabbitmqctl add_user slave1_user slave1_password
    rabbitmqctl add_vhost slave1_host
    rabbitmqctl set_permissions -p slave1_host slave1_user ".*" ".*" ".*"

    rabbitmqctl add_user slave2_user slave2_password
    rabbitmqctl add_vhost slave2_host
    rabbitmqctl set_permissions -p slave2_host slave2_user ".*" ".*" ".*"

    rabbitmqctl add_user slave3_user slave3_password
    rabbitmqctl add_vhost slave3_host
    rabbitmqctl set_permissions -p slave3_host slave3_user ".*" ".*" ".*"

    rabbitmqctl add_user slave4_user slave4_password
    rabbitmqctl add_vhost slave4_host
    rabbitmqctl set_permissions -p slave4_host slave4_user ".*" ".*" ".*"

You'll also need ``config.py`` file for each of the master and slave projects. We include a sample here for reference:

    import os

    class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')

    class DevelopmentConfig(Config):
    DEBUG = True
    SECRET_KEY = os.environ.get('SECRET_KEY') or 't0p s3cr3t'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
    'mysql+pymysql://user:password@localhost/traceless_db'
    CELERY_BROKER_URL = 'amqp://user:password@localhost:5672/vhost'

    class TestingConfig(Config):
        TESTING = True
        pass

    class ProductionConfig(Config):
        pass

    config = {
        'development': DevelopmentConfig,
        'testing': TestingConfig,
        'production': ProductionConfig,
        'default': DevelopmentConfig
    }
    
Now we can run the master server

    # RUNNING MASTER
    
    cd master
    
    # set up virtualenv
    mkvirtualenv traceless_master

    # install the project
    pip install -r requirements.txt

    # Run the server
    python traceless_master.py runserver

    # Run the celery process (in a new tab, but make sure to activate the 
    # virtualenv)
    python start_celery.py worker -A master_app --beat

Similarly we can run each slave. Remember these all need to run with different RabbitMQ virtual hosts

    # RUNNING SLAVE[N]
    
    cd slave[N]
    
    # set up virtualenv
    mkvirtualenv traceless_slave[N]

    # install the project
    pip install -r requirements.txt

    # Run the server
    python traceless_slave.py runserver

    # Run the celery process (in a new tab, but make sure to activate the 
    # virtualenv)
    python start_celery.py worker -A master_app --beat


