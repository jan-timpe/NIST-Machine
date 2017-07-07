from database.development import db
import datetime

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
	result = one({"cve.CVE_data_meta": {
			"ID": str(id)
	}})
	return result

# accepts 1 integer argument
def by_year(year):
	start = datetime.datetime(year, 1, 1, 0, 0, 0, 0)
	result = by_date(start)

	return result

# accepts 1 string argument
def description_contains(search_string):
	regex = '.*'+str(search_string)+'.*'
	result = many({
		'cve.description.desctiption_data': {
			'$elemMatch': {
				'value': {
					'$regex': regex,
					'$options': 'i'
				}
			}
		}
	})

	return result

def cpe_string_contains(search_string):
	regex = '.*'+str(search_string)+'.*'
	result = many({
		'configurations.nodes': {
			'$elemMatch': {
				'cpe': {
					'$elemMatch': {
						'cpeMatchString': {
							'$regex': regex,
							'$options': 'i'
						}
					}
				}
			}
		}
	})

	return result
