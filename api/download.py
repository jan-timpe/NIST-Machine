from database.development import db
import ijson, gzip, urllib.request

CVE_MODIFIED_URL = 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz'
CVE_RECENT_URL = 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz'

# lambda for generating year resource urls
CVE_YEAR_URL = lambda y: 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-'+str(y)+'.json.gz'

# downloads and unzips a file from a given url
# use the common url patterns above
def from_url(url):
    zipped = urllib.request.urlopen(url)
    file = gzip.open(zipped)
    return file

def from_local(filename):
    file = open(filename)
    return file

# CVE-Recent file
def recent():
    return from_url(CVE_RECENT_URL)

# CVE-Modified file
def modified():
    return from_url(CVE_MODIFIED_URL)

# CVE-{Year}
def year(year):
    return from_url(CVE_YEAR_URL(year))

# Returns an ijson object
# ijson is an iterative json parser; it keeps files on disk until accessed (random i/o)
# https://github.com/isagalaev/ijson
def to_json(file):
    objects = ijson.items(file, 'CVE_Items.item')
    return objects
