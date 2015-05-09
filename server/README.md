# Traceless Single Server  

## Prequisites

First, we need to setup the project.

    # install mysql and swig
    brew install mysql

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


