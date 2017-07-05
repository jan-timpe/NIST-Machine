import pymongo

client = pymongo.MongoClient('mongodb://database-service')
db = client.cve_items

# create an index on CVE_ID so that duplicate inserts are ignored
db.cve_items.create_index([('CVE_data_meta.CVE_ID', pymongo.ASCENDING)], unique=True)
