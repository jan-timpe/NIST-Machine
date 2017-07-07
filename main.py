import api.vulnerability_database as api
from datetime import datetime
from itertools import chain

api.refresh_all()

results = [
	api.fetch.cpe_string_contains(''),
	api.fetch.many({})
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
