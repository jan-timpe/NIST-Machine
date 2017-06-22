import api.vulnerability_database as api
from datetime import datetime

print('Starting')

api.update_recent()
print('Downloaded recent')

# api.update_modified()
# print('Downloaded modified')

# api.update_year(2017)
# print('Downloaded 2017')

# api.update_year(2015)
# print('Downloaded 2015')


print('Searching for MongoDB vulns')
# get fancy with regex to do string searching
# result = api.fetch.many({
# 	'CVE_description.CVE_description_data': {
# 		'$elemMatch': {
# 			'value': {
# 				'$regex': '.*e.*',
# 				'$options': 'i'
# 			}
# 		}
# 	}
# })

result = api.fetch.by_date(datetime(2017, 6, 20, 0, 0, 0, 0))

if result:
	print(result.count(), 'found')
	print('====')

	for item in result:
		descriptions = item['CVE_description']['CVE_description_data']
		references = item['CVE_references']['CVE_reference_data']
		print(item['CVE_data_meta']['CVE_ID'])

		for desc in descriptions:
			print(desc['value'])

		for ref in references:
			if 'publish_date' in ref:
				print(ref['publish_date'])

		print('====')
else:
	print('Nothing found')
