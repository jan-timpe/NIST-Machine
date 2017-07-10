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

### Basic setup
In ```main.py```:
```
import api.vulnerability_database as api
```

### Downloading data
Data is downloaded from the NIST.gov server using ```urllib```, then is parsed using ```ijson``` and inserted into the MongoDB instance.
```
api.update_recent() # downloads the most recently updated version of nvdcve-1.0-recent.gz
api.update_modified() # downloads and parses nvdcve-1.0-modified.gz
api.update_year(2017) # downloads and parses nvdcve-1.0-{YEAR}.gz
```

### Using the database
Once data is downloaded and inserted into the database, you can search for items using ```pymongo``` and the ```api.fetch``` module.
```
# fetches all values with 'mongodb' (case insensitive) in the CVE_description
result = api.fetch.many({
   'CVE_description.CVE_description_data': {
      '$elemMatch': {
         'value': {
            '$regex': '.*mongodb.*',
            '$options': 'i'
         }
      }
   }
})

# this will print all the CVE_ID and all description values for every object returned
for item in result:
   descriptions = item['CVE_description']['CVE_description_data']
   print(item['CVE_data_meta']['CVE_ID'])

   for desc in descriptions:
      print(desc['value'])
```

The ```api.fetch.one()``` function can be used to return a single object instead of a list. This will get the _first_ matching object
```
# fetches an object with CVE_ID equal to "CVE-2014-8180"
result = api.fetch.one({{"CVE_data_meta": {"CVE_ID": "CVE-2014-8180"}}})
```

Alternatively, use the ```api.fetch.by_id()``` function to search the database by CVE_ID and return a single object
```
result = api.fetch.by_id("CVE-2014-8180")
```
