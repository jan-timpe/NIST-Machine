import pymongo

client = pymongo.MongoClient('localhost', 27017)
db = client.cve_items

# only use in development
# deletes all of the items in the database every time the script is run
db.cve_items.delete_many({})

# create an index on CVE_ID so that duplicate inserts are ignored
db.cve_items.create_index([('CVE_data_meta.CVE_ID', pymongo.ASCENDING)], unique=True)
