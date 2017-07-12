from database.development import db
import datetime
from .models import VulnerabilityVector

#
#
def insert_or_replace_one(cve_id, item):
    # try:
    result = db.cve_items.replace_one(
        {'cve.CVE_data_meta.ID': str(cve_id)},
        item,
        True # upsert = True; inserts if not found
    )
    return result
    # except:
    #     return None


def insert_or_replace_many(items):
    for item in items:
        vuln_vector = VulnerabilityVector()
        vuln_vector.set_cve(item)
        vuln_vector.save()

        item_id = item['cve']['CVE_data_meta']['ID']

        if 'baseMetricV2' in item['impact']:
            item['impact']['baseMetricV2']['cvssV2']['baseScore'] = str(item['impact']['baseMetricV2']['cvssV2']['baseScore'])
            item['impact']['baseMetricV2']['exploitabilityScore'] = str(item['impact']['baseMetricV2']['exploitabilityScore'])
            item['impact']['baseMetricV2']['impactScore'] = str(item['impact']['baseMetricV2']['impactScore'])
            # cvss_v2 = item['impact']['baseMetricV2']

        cvss_v3 = None
        if 'baseMetricV3' in item['impact']:
            item['impact']['baseMetricV3']['cvssV3']['baseScore'] = str(item['impact']['baseMetricV3']['cvssV3']['baseScore'])
            item['impact']['baseMetricV3']['exploitabilityScore'] = str(item['impact']['baseMetricV3']['exploitabilityScore'])
            item['impact']['baseMetricV3']['impactScore'] = str(item['impact']['baseMetricV3']['impactScore'])

        insert_or_replace_one(item_id, item)
