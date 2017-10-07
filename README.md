# NIST-Machine

This project reaches to the [NIST National Vulnerability Database](https://nvd.nist.gov), retrieves a list of vulnerabilities with the given parameters, parses, and saves them into a MongoDB Database.

The project is used to generate lists of vulnerabilities and their attributes to a CSV file. Currently the list of attributes generated for the CSV are (in order):

* `matched_search`: search string used to find this object
* `cve_id`: the Common Vulnerabilities and Exposures ID
* `cvss_v3_impact_score`: [Common Vulnerability Scoring System (v3) score](https://www.first.org/cvss/specification-document#1-2-Scoring)
* `cvss_v3_string`: [CVSS vector string](https://www.first.org/cvss/specification-document#6-Vector-String)
* `cvss_v2_impact_score`: [CVSS v2 scoring](https://www.first.org/cvss/v2/guide#3-Scoring)
* `cvss_v2_string`: [CVSS v2 vector string](https://www.first.org/cvss/v2/guide#2-4-Base-Temporal-Environmental-Vectors)
* `cwe_id`: [Common Weakness Enumeration](https://cwe.mitre.org/about/index.html) 
* `last_modified`
* `description`
* `matched_uris`: URIs that were matched using the `matched_search` string

The fields included in the CSV can be parsed and enumerated to aid in analysis. The `cvss_v2_string` and `cvss_v3_string` can be further parsed to obtain the individual metrics associated with the vulnerability. The rows output by the program, as well as any additional parsing that needs to be done before outputting rows to the CSV, can be done in `models.py` in `Vulnerability.as_csv_row()`. Documentation and raw data feeds can be found on the [NVD website](https://nvd.nist.gov/vuln/data-feeds)

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

### Querying
[MongoEngine](http://docs.mongoengine.org/) is used to store Vulnerability Vectors generated from the NVD dataset. Filtering can be done by calling
```
from api.models import VulnerabilityVector

result = VulnerabilityVector.objects.filter(**kwargs)
```

See the [MongoEngine querying docs](http://docs.mongoengine.org/guide/querying.html) for more usage instructions

### Using the application
Start the app with python in the command line:

```
(venv) $ python3 main.py
```

There are several command line arguments available. Some are required.

#### Command line arguments
`-h` or `--help`: Prints usage help to the console
```
(venv) $ python3 main.py -h
(venv) $ python3 main.py --help
```

`-r` or `--refresh`: Drops all collections and re-initializes the database with newly downloaded information from the NVD (this takes a while to complete)
```
(venv) $ python3 main.py -r
(venv) $ python3 main.py --refresh
```

`-i` or `--input=` (followed by a filename): Specify an input file. Input files must be a list of complete or partial `cpeMatchString` from the NVD datasets. Each string should be on its own line with no other separators or delimiters.
```
(venv) $ python3 main.py -i input.txt
(venv) $ python3 main.py --input=input.txt
```

`-o` or  `--output=` (followed by a filename): Specify an output file. The programs output is the result of applying the filters you specify in command line arguments to the objects in the local database. Each object is turned into a CSV row of the following format

`[ cve_id],[ cwe_id ],[ first cpeMatchString ],[ all cpe values ],[ last modified date ],[ cvss_v2 vectorString ],[ cvss_v3 vectorString ],[ vulnerability description ]`

If no output filename is specified, the default `output.csv` is used

```
(venv) $ python3 main.py -o output.csv
(venv) $ python3 main.py --output=output.csv
```

`-d` or `--days=` (followed by an integer): Search vulnerabilities from between the specified number of days ago and the current date
(e.g., calling `python3 main.py -d 30` will search vulnerabilities from within the last 30 days)
```
(venv) $ python3 main.py -d 30
(venv) $ python3 main.py --days=30
```

`-y` or `--year=` (followed by an integer): Search vulnerabilities from within the specified year
```
(venv) $ python3 main.py -y 2017
(venv) $ python3 main.py --year=2017
```

`-s` or `--search=` (followed by a complete or partial `cpeMatchString`): Search the database for a single `cpeMatchString`. Usage is the same as for an input file, except with only one search performed.
```
(venv) $ python3 main.py -s mysql
(venv) $ python3 main.py --search mysql
```

#### Using multiple argument filters
You can use multiple arguments to further filter your result set. However, some conflict. When conflicting arguments are supplied, the following behavior occurs

* `year` will take precedence over `days`
* `input` will take precedence over `search`

Example: The following will search MySQL vulnerabilities from the last 30 days
```
(venv) $ python3 main.py -s mysql -d 30
```
