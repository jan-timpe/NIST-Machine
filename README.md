# NIST-Machine

This project reaches to the NIST National Vulnerability Database, retrieves the most recent list of vulnerabilities, parses, and saves them into a MongoDB Database

## Get up and running
### Create a virtual environment

Windows
```
$ mkvirtualenv NvdApi
$ setprojectdir .
```

macOS
```
$ virtualenv venv
$ source ./venv/bin/activate
```

To deactivate an environment
```
$ deactivate
```

To reactivate
Windows:
```
$ workon NvdApi
```
Mac:
```
$ source ./path/to/project/venv/bin/activate
```

### Install the requirements
*Note*: Make sure to use ```pip3``` when installing and managing packages, and ```python3``` to run the project

With your virtual environment active, run:
```
$ pip3 install -r requirements.txt
```

Follow [this guide](https://docs.mongodb.com/master/administration/install-community/) to install MongoDB locally, or install it on another server and update the credentials in the ```database``` module

Start the Mongo server by running
```
$ mongod
```

### Run the project
Run the project using Python 3:
```
$ python3 main.py
```

## Usage
_On its way_
