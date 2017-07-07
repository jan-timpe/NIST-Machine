from mongoengine import *
connect('cve_items')

class VulnerabilityVector:
	def __init__(self, cve_item):
		self.set_cve_id(cve_item)
		self.set_cve_description(cve_item)
		self.set_cve_references(cve_item)
		self.set_cpe_data(cve_item)
		self.set_cvss_v2(cve_item)
		self.set_cvss_v3(cve_item)
		self.set_cwe_id(cve_item)
		self.set_last_modified(cve_item)

	##
	##

	def set_cve_id(self, item):
		self.cve_id = None

		if 'cve' in item and 'CVE_data_meta' in item['cve'] and 'ID' in item['cve']['CVE_data_meta']:
			self.cve_id = item['cve']['CVE_data_meta']['ID']

	def set_cve_description(self, item):
		self.cve_description = None

		if 'cve' in item and 'description' in item['cve'] and 'description_data' in item['cve']['description']:
			descriptions = item['cve']['description']['description_data']

			for desc in descriptions:
				if 'lang' in desc and 'value' in desc and desc['lang'] == 'en':
					self.cve_description = desc['value']

	def set_cve_references(self, item):
		self.cve_references = None

		if 'cve' in item and 'references' in item['cve'] and 'reference_data' in item['cve']['references']:
			self.cve_references = item['cve']['references']['reference_data']

	def set_cpe_data(self, item):
		self.cpe_data = []

		if 'cve' in item and 'configurations' in item['cve'] and 'nodes' in item['cve']['configurations']:
			nodes = item['cve']['configurations']['nodes']

			for node in nodes:
				if 'cpe' in node:
					for child in node['cpe']:
						self.cpe_data.append(child)

	def set_cvss_v2(self, item):
		self.cvss_v2 = None

		if 'impact' in item and 'baseMetricV2' in item['impact'] and 'cvssV2' in item['impact']['baseMetricV2']:
			cvss = item['impact']['baseMetricV2']['cvssV2']

			if 'baseScore' in cvss:
				cvss['baseScore'] = str(cvss['baseScore'])

			if 'exploitabilityScore' in cvss:
				cvss['exploitabilityScore'] = str(cvss['exploitabilityScore'])

			if 'impactScore' in cvss:
				cvss['impactScore'] = str(cvss['impactScore'])

			self.cvss_v2 = cvss

	def set_cvss_v3(self, item):
		self.cvss_v3 = None

		if 'impact' in item and 'baseMetricV3' in item['impact'] and 'cvssV3' in item['impact']['baseMetricV3']:
			cvss = item['impact']['baseMetricV3']['cvssV3']

			if 'baseScore' in cvss:
				cvss['baseScore'] = str(cvss['baseScore'])

			if 'exploitabilityScore' in cvss:
				cvss['exploitabilityScore'] = str(cvss['exploitabilityScore'])

			if 'impactScore' in cvss:
				cvss['impactScore'] = str(cvss['impactScore'])

			self.cvss_v3 = cvss

	def set_cwe_id(self, item):
		self.cwe_id = None

		if 'cve' in item and 'problemtype' in item['cve'] and 'problemtype_data' in item['cve']['problemtype']:

			problemtype_data = item['cve']['problemtype']['problemtype_data']

			for prb in problemtype_data:
				if 'description' in prb:
					for desc in prb['description']:
						if 'lang' in desc and 'value' in desc and desc['lang'] == 'en':
							self.cwe_id = desc['value']

	def set_last_modified(self, item):
		self.last_modified = None

		if 'lastModifiedDate' in item:
			self.last_modified = datetime.datetime.strptime(item['lastModifiedDate'], '%Y-%m-%dT%H:%MZ')


	##
	##

	def as_dict(self):
		return {
			'cve_id': self.cve_id,
			'cve_description': self.en_desc,
			'cve_reference_data': self.references,
			'cpe_data': self.cpe_data,
			'cvss_v2': self.cvss_v2,
			'cvss_v3': self.cvss_v3,
			'cwe_id': self.cwe_id,
			'last_modified': self.last_modified
		}

	def get_cpe_string(self):
		if len(self.cpe_data) > 0 and 'cpeMatchString' in self.cpe_data[0]:
			return self.cpe_data[0]['cpeMatchString']

		return None

	def as_csv_row(self):
		# Cpe string 1, CVE_ID, CVE_impact_cvssv3, CVE_impact_cvssv2, CWE_ID, publish time, cpe, vulnerability description
		return cpe_data[0]
