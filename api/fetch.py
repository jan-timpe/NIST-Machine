# API interface to NIST National Vulnerability Database
# fetches most recent published data available on website (updated daily)
# objects are inserted into a mongodb instance, defined in the database module

from database.development import db
import requests, ijson, gzip, urllib

#

# the most recent vulnerabilities are published on the NIST NVD website daily (gzipped)
# download the most recent release, return the unzipped file
def download_recent():
	zipped = urllib.request.urlopen('https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz')
	file = gzip.open(zipped)

	return file

# retrieves a list of objects from the mongodb instance matching the passed in arguments
# arguments must take the format {'key-to-search': { 'embedded-key-to-search': 'result-to-look-for' } }
def fetch_many(args):
	result = db.cve_items.find(args)

	return result

# retrieves the first object from the mongodb instance matching the passed in arguments
# arguments must take the format {'key-to-search': { 'embedded-key-to-search': 'result-to-look-for' } }
def fetch_one(args):
	result = db.cve_items.find_one(args)

	return result

# inserts a list of CVE Items to the mogodb instance
# does NOT check for duplicate CVE_IDs!
# FIXME: check for duplicate CVE_IDs
def insert_many_cves(items):
	result = db.cve_items.insert_many(items)

	return result

# inserts one cve item to the mongo database
# does NOT check for duplicate CVE_ID
# FIXME: check for duplicates
def insert_one_cve(item):
	result = db.cve_items.insert_one(item)

	return result

# parses an open file, downloaded and unzipped, from the NVD site
# returns an ijson object generator
# leaves the file on disk to avoid memory issues
def parse_cve_json(file):
	objects = ijson.items(file, 'CVE_Items.item')

	return objects

#

# takes an ijson object generator and loads groups of
 # objects into memory to be inserted into the database
def insert_by_chunk(obj_generator, size = 100):
	chunk = []
	for item in obj_generator:
		chunk.append(item)

		if len(chunk) >= size:
			insert_many_cves(chunk)
			del chunk[:]

	if len(chunk) > 0:
		insert_many_cves(chunk)

# downloads, parses, and inserts the most recent NVD vulnerabilities into the local db
def download_and_insert_recent():
	file = download_recent()
	objects = parse_cve_json(file)
	insert_by_chunk(objects)

# opens a local file and inserts the NVD vulnerabilities into the local db
def open_local_and_insert(filename):
	file = open(filename, 'r')
	objects = parse_cve_json(file)
	insert_by_chunk(objects)

