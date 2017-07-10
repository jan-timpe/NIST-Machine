import api.vulnerability_database as api
from datetime import datetime
from itertools import chain
from api.models import VulnerabilityVector

api.refresh_all()

results = [
    api.fetch.by_year(2017)
]

for result in results:
    if result:
        print(result.count(), 'found')
    else:
        print('Nothing found')

for result in VulnerabilityVector.objects(cve_id='CVE-2004-2778'):
    print(result.as_csv_row())
