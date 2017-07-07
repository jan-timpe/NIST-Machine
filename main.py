import api.vulnerability_database as api
from datetime import datetime
from itertools import chain

def print_cve_item(item):
	cve_id = item['CVE_data_meta']['CVE_id']

	descriptions = item['CVE_description']['CVE_description_data']

	references = item['CVE_references']['CVE_reference_data']
	publish_date = references[0]['publish_date']
	last_update = references[-1]['publish_date']

	cpe = item['CVE_configurations']['CVE_configuration_data']['cpe']

	cve_impact = item['CVE_impact']
	cve_impact_cvssv2 = cve_impact['CVE_impact_cvssv2']
	cve_impact_cvssv3 = cve_impact['CVE_impact_cvssv3']

	cwe_id = item['CVE_problemtype']['CVE_problemtype_data'][0]['description']['value']

# api.refresh_all()

results = [
	api.fetch.by_date(datetime(2017, 6, 20, 0, 0, 0, 0)),
	api.fetch.by_year(2017),
	api.fetch.cpe_string_contains('php:php'),
]

for result in results:
	if result:
		print(result.count(), 'found')
	else:
		print('Nothing found')



# Cpe string 1,
# - CVE_ID,
# - CVE_impact_cvssv3,
# - CVE_impact_cvssv2,
# - CWE_ID,
# - publish time,
# - cpe,
# - vulnerability description
