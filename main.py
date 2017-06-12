import api.vulnerability_database as api

print('Starting')

# api.update_recent()
# print('Downloaded recent')

# api.update_modified()
# print('Downloaded modified')

# api.update_year(2017)
# print('Downloaded 2017')

# api.update_year(2015)
# print('Downloaded 2015')


print('Searching for MongoDB vulns')
# get fancy with regex to do string searching
# regex = re.compile(r'/.*mongodb.*/i')
result = api.fetch.many({
	'CVE_description.CVE_description_data': {
		'$elemMatch': {
			'value': {
				'$regex': '.*mongodb.*',
				'$options': 'i'
			}
		}
	}
})



print(result.count(), 'found')
print('====')

for item in result:
	descriptions = item['CVE_description']['CVE_description_data']
	print(item['CVE_data_meta']['CVE_ID'])

	for desc in descriptions:
		print(desc['value'])

	print('====')
