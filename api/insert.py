import api.fetch
import datetime
from .models import VulnerabilityVector

# 
def insert_or_replace_many(items):
    for item in items:
        item_id = item['cve']['CVE_data_meta']['ID']

        vuln_vector = api.fetch.by_id(item_id)

        if not vuln_vector:
            vuln_vector = VulnerabilityVector()

        vuln_vector.set_cve(item)
        vuln_vector.save()
