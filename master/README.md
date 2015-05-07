heckup-Backend

## Prequisites

First, we need to setup the project.

    # install mysql and swig
    brew install mysql
    brew install swig
    brew install rabbitmq

    # set up virtualenv
    mkvirtualenv traceless

    # install the project
    pip install -r requirements.txt

    # create mysql database
    mysql -u root
    create database traceless_db;
    exit;

    # Run the server
    python traceless_server.py runserver
    ##### python checkup_web.py runserver --host 0.0.0.0 
