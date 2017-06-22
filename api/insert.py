from database.development import db
import datetime

def preprocess(item):
	for ref in item['CVE_references']['CVE_reference_data']:
		if 'publish_date' in ref:
			ref['publish_date'] = datetime.datetime.strptime(ref['publish_date'], "%m/%d/%Y")

	return item

# inserts a list of CVE Items to the mogodb instance
# checks for duplicate CVE_IDs with an index defined in the database package
def one(item):
	try:
		result = db.cve_items.insert_one(item)
		return result
	except:
		return None

# inserts one cve item to the mongo database
# checks for duplicate CVE_IDs with an index defined in the database package
def many(items):
	items = preprocess(items)
	try:
		result = db.cve_items.insert_many(items)
		return result
	except:
		return None

# takes an ijson object generator and loads groups of
# objects into memory to be inserted into the database
def group(obj_generator, size = 100):
	obj_generator = preprocess(obj_generator)
	g = []
	for item in obj_generator:
		g.append(item)

		if len(g) >= size:
			many(g)
			del g[:]

	if len(g) > 0:
		many(g)

#
#
def insert_or_replace_one(cve_id, item):
	try:
		result = db.cve_items.replace_one({'CVE_data_meta': {'CVE_ID': str(cve_id)}}, item, True)
		return result
	except:
		return None

def insert_or_replace_many(items):
	for item in items:
		item = preprocess(item)
		item_id = item['CVE_data_meta']['CVE_ID']
		insert_or_replace_one(item_id, item)
