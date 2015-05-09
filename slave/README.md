# Traceless Slave

## Prequisites

First, we need to set up the slave server project.

    # install mysql and rabbitmq
    brew install mysql
    brew install rabbitmq

    # set up virtualenv
    mkvirtualenv traceless_slave

    # install the project
    pip install -r requirements.txt
    
    # create mysql database
    mysql -u root
    create database traceless_db;
    exit;
    
    # setup rabbitmq for celery
    rabbitmqctl add_user slave_user slave_password
    rabbitmqctl add_vhost slave_host
    rabbitmqctl set_permissions -p slave_host slave_user ".*" ".*" ".*"

    # Run the slave server
    python traceless_server.py runserver
    
    # In a different terminal tab, run the celery process
    python start_celery.py worker -A app --beat
