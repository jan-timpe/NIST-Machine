from datetime import datetime
from mongoengine import *
connect('cve_items')

class VulnerabilityVector(Document):
    cve_id = StringField(max_length=20, required=True, unique=True)
    en_desc = StringField()
    references = ListField(DictField())
    cpe_data = ListField(DictField())
    cvss_v2 = DictField()
    cvss_v3 = DictField()
    cwe_id = StringField(max_length=20)
    last_modified = DateTimeField()

    def set_cve(self, cve_item):
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
        if 'cve' in item and 'CVE_data_meta' in item['cve'] and 'ID' in item['cve']['CVE_data_meta']:
            self.cve_id = item['cve']['CVE_data_meta']['ID']

    def set_cve_description(self, item):
        if 'cve' in item and 'description' in item['cve'] and 'description_data' in item['cve']['description']:
            descriptions = item['cve']['description']['description_data']

            for desc in descriptions:
                if 'lang' in desc and 'value' in desc and desc['lang'] == 'en':
                    self.en_desc = desc['value']

    def set_cve_references(self, item):
        if 'cve' in item and 'references' in item['cve'] and 'reference_data' in item['cve']['references']:
            self.cve_references = item['cve']['references']['reference_data']

    def set_cpe_data(self, item):
        if 'configurations' in item and 'nodes' in item['configurations']:
            nodes = item['configurations']['nodes']

            for node in nodes:
                if 'cpe' in node:
                    for child in node['cpe']:
                        self.cpe_data.append(child)

    def set_cvss_v2(self, item):
        if 'impact' in item and 'baseMetricV2' in item['impact'] and 'cvssV2' in item['impact']['baseMetricV2']:
            cvss = item['impact']['baseMetricV2']['cvssV2']

            if 'baseScore' in cvss:
                cvss['baseScore'] = str(cvss['baseScore'])

            self.cvss_v2 = cvss

    def set_cvss_v3(self, item):
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
        if 'cve' in item and 'problemtype' in item['cve'] and 'problemtype_data' in item['cve']['problemtype']:

            problemtype_data = item['cve']['problemtype']['problemtype_data']

            for prb in problemtype_data:
                if 'description' in prb:
                    for desc in prb['description']:
                        if 'lang' in desc and 'value' in desc and desc['lang'] == 'en':
                            self.cwe_id = desc['value']

    def set_last_modified(self, item):
        if 'lastModifiedDate' in item:
            self.last_modified = datetime.strptime(item['lastModifiedDate'], '%Y-%m-%dT%H:%MZ')


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

    def get_cpe_match_string(self, index):
        if len(self.cpe_data) > index and 'cpeMatchString' in self.cpe_data[index]:
            return self.cpe_data[index]['cpeMatchString']

        return 'None'

    def get_cpe_string(self, delim=';'):
        cpe = []

        for node in self.cpe_data:
            node_data = []
            for k in node:
                node_data.append(str(k)+':'+str(node[k]))

            node_string = delim.join(node_data)
            cpe.append(node_string)

        if len(cpe) > 0:
            cpe_string = (delim+delim).join(cpe)
            return cpe_string

        return 'None'

    def get_cvss_v2_impact_score(self): 
        if len(self.cvss_v2) > 0 and 'baseScore' in self.cvss_v2:
            return str(self.cvss_v2['baseScore'])

        return 'None'

    def get_cvss_v2_string(self):
        if len(self.cvss_v2) > 0 and 'vectorString' in self.cvss_v2:
            return self.cvss_v2['vectorString']

        return 'None'

    def get_cvss_v3_impact_score(self): 
        if len(self.cvss_v3) > 0 and 'baseScore' in self.cvss_v3:
            return str(self.cvss_v3['baseScore'])

        return 'None'

    def get_cvss_v3_string(self):
        if len(self.cvss_v3) > 0 and 'vectorString' in self.cvss_v3:
            return self.cvss_v3['vectorString']

        return 'None'

    def get_last_modified_string(self):
        if self.last_modified:
            return self.last_modified.strftime('%Y-%m-%d %H:%M:%S')

        return 'None'

    def get_stripped_description(self, delim):
        if self.en_desc:
            return self.en_desc.replace(delim, '')

        return 'None'

    def get_matched(self, search_strings):
        matched_search_string = 'None'
        matched_uri_string = 'None'

        if len(search_strings) > 0:
            matched_searches = []
            matched_uris = []

            cpe_uris = [d['cpe23Uri'] for d in self.cpe_data]
            for string in search_strings:
                for uri in cpe_uris:
                    if string in uri:
                        matched_searches.append(string)
                        matched_uris.append(uri)

            if len(matched_searches) > 0:
                matched_search_string = matched_searches[0]

            if len(matched_uris) > 0:
                matched_uri_string = ';'.join(matched_uris)
            
        return matched_search_string, matched_uri_string

    def as_csv_row(self, search_strings=[], delim=','): 
        csv_row = []

        matched_search, matched_uris = self.get_matched(search_strings)

        # search string
        csv_row.append(matched_search)

        # CVE_ID
        if self.cve_id:
            csv_row.append(self.cve_id)
        else:
            csv_row.append('None')

        # CVE_impact_cvssv3_score
        csv_row.append(self.get_cvss_v3_impact_score())

        # CVE_impact_cvssv3_bm
        csv_row.append(self.get_cvss_v3_string())

        # CVE_impact_cvssv2_score, 
        csv_row.append(self.get_cvss_v2_impact_score())

        # CVE_impact_cvssv2_bm
        csv_row.append(self.get_cvss_v2_string())

        # CWE_ID
        if self.cwe_id:
            csv_row.append(self.cwe_id)
        else:
            csv_row.append('None')

        # publish time
        csv_row.append(self.get_last_modified_string())

        # vulnerability description
        csv_row.append(self.get_stripped_description(delim))
            
        # cpe
        csv_row.append(matched_uris)

        return delim.join(csv_row)
