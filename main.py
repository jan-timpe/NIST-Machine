from api.models import VulnerabilityVector
import api.vulnerability_database as api
import sys, getopt

def die_with_usage_help():
    print('usage: main.py -i <input> -o <output>')

def get_startup_options(args):
    # opt_list # do something with this

def main(args):
    input_file = None
    output_file = None

    try:
        opts, args = getopt.getopt(argv,"rhi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print 'test.py -i <inputfile> -o <outputfile>'
        sys.exit(2)

arg1 = sys.argv[1]
arg2 = sys.argv[2]

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
