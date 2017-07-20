from api.models import VulnerabilityVector
import api.vulnerability_database as api
from datetime import datetime, timedelta
import re
import sys, getopt

# returns a regex wildcard search object
def get_cpe_search_object(search_string):
    regex_string = '.*'+str(search_string.strip('\n'))+'.*'
    return re.compile(regex_string)

# returns a list of regex wildcard search objects
# format of the input file should be one cpe search string per line, with no other separators or delimiters
def parse_cpe_search_file(filename):
    f = open(filename, 'r')

    cpe_search_objects = []
    cpe_search_strings = []
    for line in f:
        cpe_search_strings.append(line)
        cpe_search_objects.append(get_cpe_search_object(line))

    f.close()
    return (cpe_search_strings, cpe_search_objects)

# prints out a list of VulnerabilityVector objects turned into csv rows
def output_to_csv(filename, vuln_vectors, search_strings=[], search_string=''):
    result = ['CPE_String, Matched searches, CVE_ID, CVE_impact_cvssv3, CVE_impact_cvssv2, CWE_ID, Last_modified, CPE, Description']
    f = open(filename, 'w')
    for v in vuln_vectors:
        if len(search_string) > 0 and len(search_strings) == 0:
            search_strings.append(search_string)

        result.append(v.as_csv_row(search_strings=search_strings))
    f.write('\n'.join(result))
    f.close()

def die_with_usage_help():
    print('usage: main.py -i <input_file> -o <output_file> -d <days_ago> -y <year> -s <cpe_string>')
    sys.exit(2)

def get_startup_options(argv):
    search_strings = []
    input_file = None
    output_file = None
    search_date = None
    search_year = None
    search_string = None

    try:
        opts, args = getopt.getopt(argv,'rhi:d:y:o:s:', ['refresh', 'input=', 'output=', 'days=', 'year=', 'help', 'search='])
    except getopt.GetoptError:
        die_with_usage_help()

    for opt, arg in opts:
        if opt in ('-r', '--refresh'):
            # refresh the database
            print('Refreshing data...')
            api.refresh_all()
        elif opt in ('-i', '--input'):
            # specify an input file
            input_file = arg
        elif opt in ('-o', '--output'):
            # specify an output file
            output_file = arg
        elif opt in ('-d', '--days'):
            # search by date (betwee x days ago and today)
            delta = timedelta(**{'days': float(arg)})
            search_date = datetime.now() - delta
        elif opt in ('-y', '--year'):
            # search by year
            search_year = int(arg)
        elif opt in ('-h', '--help'):
            # print usage help
            die_with_usage_help()
        elif opt in ('-s', '--search'):
            # search by single cpe string
            search_string = arg

    return (input_file, output_file, search_date, search_year, search_string, search_strings)


# run the main program; accepts command line arguments and prints the final result set out to an output file in csv format
def main(argv):
    input_file, output_file, search_date, search_year, search_string, search_strings = get_startup_options(argv)

    # either an input file, days ago, year, or search string value must be provided
    if not input_file and not search_date and not search_year and not search_string:
        print('invalid configuration')
        die_with_usage_help()


    # MongoDB does not support filter chaining for queries with multiple regex searches
    # to work around that, we build a raw query progressively and do a single filter
    # with all of the requested parameters.

    query = {}

    # file input will take precedence over a string argument if both are provided
    if input_file:
        start = datetime(2017, 1, 1, 0, 0, 0, 0)
        end = datetime(2018, 12, 31, 23, 59, 59)
        search_objects = parse_cpe_search_file(input_file)
        query['cpe_data'] = {
            '$elemMatch': {
                    'cpe23Uri': {
                    '$in': search_objects
                }
            }
        }
    elif search_string:
        query['cpe_data'] = {
            '$elemMatch': {
                'cpe23Uri': {
                    '$regex': '.*'+str(search_string)+'.*',
                    '$options': 'i'
                }
            }
        } 

    # year search will take precedence over date search if both are provided
    if search_year:
        start = datetime(search_year, 1, 1, 0, 0, 0, 0)
        end = datetime(search_year, 12, 31, 23, 59, 59)
        query['last_modified'] = {
            '$gte': start,
            '$lte': end
        }
    elif search_date:
        end=datetime.now()
        query['last_modified'] = {
            '$gte': search_date,
            '$lte': end
        }

    #

    result = VulnerabilityVector.objects(__raw__=query)
        
    # a default output file name
    if not output_file:
        output_file = 'output.csv'

    print('Generating csv...')
    output_to_csv(output_file, result, search_strings=search_strings, search_string=search_string)

# pass the arguments into the main function when the script starts
if __name__ == "__main__":
   main(sys.argv[1:])
