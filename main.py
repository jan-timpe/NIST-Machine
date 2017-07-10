from api.models import VulnerabilityVector
import api.vulnerability_database as api
import sys, getopt

api.refresh_all()

results = [
    api.fetch.cpe_string_contains('gentoo'),
    api.fetch.by_year(2017)
]

for result in results:
    if result:
        print(result.count(), 'found')
    else:
        print('Nothing found')

for result in VulnerabilityVector.objects(cve_id='CVE-2004-2778'):
    print(result.as_csv_row())
