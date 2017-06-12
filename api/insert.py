from database.development import db

# FIXME: look into ways to update an existing CVE_Item on insert rather than ignore it
# vulnerabilities could have been updated since last download

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
	try:
		result = db.cve_items.insert_many(items)
		return result
	except:
		return None

# takes an ijson object generator and loads groups of
# objects into memory to be inserted into the database
def group(obj_generator, size = 100):
	g = []
	for item in obj_generator:
		g.append(item)

		if len(g) >= size:
			many(g)
			del g[:]

	if len(g) > 0:
		many(g)
