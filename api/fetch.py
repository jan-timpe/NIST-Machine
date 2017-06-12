from database.development import db

# retrieves a list of objects from the mongodb instance matching the passed in arguments
# arguments must take the format {'key-to-search': { 'embedded-key-to-search': 'result-to-look-for' } }
def many(args):
	result = db.cve_items.find(args)
	return result

# retrieves the first object from the mongodb instance matching the passed in arguments
# arguments must take the format {'key-to-search': { 'embedded-key-to-search': 'result-to-look-for' } }
def one(args):
	result = db.cve_items.find_one(args)
	return result

# retrieves one CVE_Item given a CVE_ID (primary key)
def by_id(id):
	result = one({"CVE_data_meta": {
			"CVE_ID": str(id)
	}})
	return result
