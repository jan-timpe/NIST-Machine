import pymongo

client = pymongo.MongoClient('mongodb://localhost')
db = client.cve_items

db.cve_items.delete_many({})

# create an index on CVE_ID so that duplicate inserts are ignored
try:
    db.cve_items.drop_indexes()
except:
    print('could not drop index')

db.cve_items.create_index([('cve.CVE_data_meta.ID', pymongo.ASCENDING)], unique=True)
