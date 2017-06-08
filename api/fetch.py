from database.development import db
import requests, ijson, gzip, urllib

def read_local_file(filename):
	file = open(filename, 'r')
	objects = ijson.items(file, 'CVE_Items.item')

	# cities = (o for o in objects if o['type'] == 'city') # this will be useful i'm sure
	n = 100
	chunk = []
	for item in objects:
		chunk.append(item)

		if len(chunk) >= n:
			insert_cve_chunk(chunk)
			del chunk[:]

	if len(chunk) > 0:
		insert_cve_chunk(chunk)

def fetch_recent():
	zipped = urllib.request.urlopen('https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz')
	file = gzip.open(zipped)
	objects = ijson.items(file, 'CVE_Items.item')

	n = 100
	chunk = []
	for item in objects:
		chunk.append(item)

		if len(chunk) >= n:
			insert_cve_chunk(chunk)
			del chunk[:]

	if len(chunk) > 0:
		insert_cve_chunk(chunk)

def insert_cve_chunk(chunk):
	new_result = db.cve_items.insert_many(chunk)

def retrieve():
	result = db.cve_items.find_one({"CVE_data_meta": {"CVE_ID": "CVE-2014-0097"}})
	return result
