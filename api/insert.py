from database.development import db
import datetime

# goal for these methods is to have a standardized format for parsing.
def get_cve_en_description(descriptions):
	for desc in descriptions:
		if 'lang' in desc and desc['lang'] == 'en':
			return desc['value']
	return None

def get_cve_config_cpe(config_data):
	cpe_data = []
	for node in config_data:
		if 'cpe' in node:
			for child in node['cpe']:
				cpe_data.append(child)

	return cpe_data

def get_cve_en_cwe_id(problemtype_data):
	for prb in problemtype_data:
		if 'description' in prb:
			for desc in prb['description']:
				if 'lang' in desc and desc['lang'] == 'en':
					return desc['value']
	return None

def create_vulnerability_vector(item):
	cve_id = item['cve']['CVE_data_meta']['ID']

	descriptions = None
	en_desc = None
	if 'description' in item['cve']:
		if 'description_date' in item['cve']['description']:
			descriptions = item['cve']['description']['description_data']
			en_desc = get_cve_en_description(descriptions)

	if 'references' in item['cve']:
		if 'reference_data' in item['cve']['references']:
			references = item['cve']['references']['reference_data']

	cpe_data = get_cve_config_cpe(item['configurations']['nodes'])

	cvss_v2 = None
	if 'baseMetricV2' in item['impact']:
		item['impact']['baseMetricV2']['cvssV2']['baseScore'] = str(item['impact']['baseMetricV2']['cvssV2']['baseScore'])
		item['impact']['baseMetricV2']['exploitabilityScore'] = str(item['impact']['baseMetricV2']['exploitabilityScore'])
		item['impact']['baseMetricV2']['impactScore'] = str(item['impact']['baseMetricV2']['impactScore'])
		cvss_v2 = item['impact']['baseMetricV2']

	cvss_v3 = None
	if 'baseMetricV3' in item['impact']:
		item['impact']['baseMetricV3']['cvssV3']['baseScore'] = str(item['impact']['baseMetricV3']['cvssV3']['baseScore'])
		item['impact']['baseMetricV3']['exploitabilityScore'] = str(item['impact']['baseMetricV3']['exploitabilityScore'])
		item['impact']['baseMetricV3']['impactScore'] = str(item['impact']['baseMetricV3']['impactScore'])
		cvss_v3 = item['impact']['baseMetricV3']

	cwe_id = get_cve_en_cwe_id(item['cve']['problemtype']['problemtype_data'])

	last_modified = None
	if 'lastModifiedDate' in item:
		last_modified = datetime.datetime.strptime(item['lastModifiedDate'], '%Y-%m-%dT%H:%MZ')
		item['lastModifiedDate'] = last_modified

	return {
		'cve_id': cve_id,
		'cve_description': en_desc,
		'cve_reference_data': references,
		'cpe_data': cpe_data,
		'cvss_v2': cvss_v2,
		'cvss_v3': cvss_v3,
		'cwe_id': cwe_id,
		'last_modified': last_modified
	}

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
	# 	return None


def insert_or_replace_many(items):
	for item in items:
		item['vulnerability_vector'] = create_vulnerability_vector(item)
		item_id = item['cve']['CVE_data_meta']['ID']
		insert_or_replace_one(item_id, item)
