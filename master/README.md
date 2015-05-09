# Traceless Master

## Prequisites

First, we need to set up the master server project.

    # install mysql and rabbitmq
    brew install mysql
    brew install rabbitmq

    # set up virtualenv
    mkvirtualenv traceless_master

    # install the project
    pip install -r requirements.txt

    # create mysql database
    mysql -u root
    create database traceless_db;
    exit;

    # setup rabbitmq for celery
    rabbitmqctl add_user master_user master_password
    rabbitmqctl add_vhost master_host
    rabbitmqctl set_permissions -p master_host master_user ".*" ".*" ".*"

    # Run the master server
    python traceless_server.py runserver

    # In a different terminal tab, run the celery process
    python start_celery.py worker -A master_app --beat