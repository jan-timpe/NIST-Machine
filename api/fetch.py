from database.development import db
import requests, ijson, gzip, urllib

#

def download_recent():
	zipped = urllib.request.urlopen('https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz')
	file = gzip.open(zipped)

	return file

def fetch_many(args):
	result = db.cve_items.find(args)

	return result

def fetch_one(args):
	result = db.cve_items.find_one(args)

	return result

def insert_many_cves(items):
	result = db.cve_items.insert_many(items)

	return result

def insert_one_cve(item):
	result = db.cve_items.insert_one(item)

	return result

def parse_cve_json(file):
	objects = ijson.items(file, 'CVE_Items.item')

	return objects

#

def insert_by_chunk(obj_generator, size = 100):
	chunk = []
	for item in obj_generator:
		chunk.append(item)

		if len(chunk) >= size:
			insert_many_cves(chunk)
			del chunk[:]

	if len(chunk) > 0:
		insert_many_cves(chunk)

def download_and_insert_recent():
	file = download_recent()
	objects = parse_cve_json(file)
	insert_by_chunk(objects)

def open_local_and_insert(filename):
	file = open(filename, 'r')
	objects = parse_cve_json(file)
	insert_by_chunk(objects)

