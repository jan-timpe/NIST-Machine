import api.vulnerability_database as api
from datetime import datetime

def print_cve_item(item):
	cve_id = item['CVE_data_meta']['CVE_id']
	descriptions = item['CVE_description']['CVE_description_data']
	references = item['CVE_references']['CVE_reference_data']

# api.refresh_all()

results = [
	api.fetch.by_date(datetime(2017, 6, 20, 0, 0, 0, 0)),
	api.fetch.by_year(2017),
	api.fetch.description_contains('e')
]

for result in results:
	if result:
		print(result.count(), 'found')
	else:
		print('Nothing found')
