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
    for line in f:
        cpe_search_objects.append(get_cpe_search_object(line))

    f.close()
    return cpe_search_objects

# prints out a list of VulnerabilityVector objects turned into csv rows
def output_to_csv(filename, vuln_vectors):
    f = open(filename, 'w')
    result = [v.as_csv_row() for v in vuln_vectors]
    f.write('\n'.join(result))
    f.close()

def die_with_usage_help():
    print('usage: main.py -i <input_file> -o <output_file> -d <days_ago> -y <year> -s <cpe_string>')
    sys.exit(2)

def get_startup_options(argv):
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

    return (input_file, output_file, search_date, search_year, search_string)


# run the main program; accepts command line arguments and prints the final result set out to an output file in csv format
def main(argv):
    input_file, output_file, search_date, search_year, search_string = get_startup_options(argv)

    # either an input file, days ago, year, or search string value must be provided
    if not input_file and not search_date and not search_year and not search_string:
        print('invalid configuration')
        die_with_usage_help()


    # start with all the objects and filter progressively based on command line arguments
    result = VulnerabilityVector.objects()

    # year search will take precedence over date search if both are provided
    if search_year:
        result = api.fetch.by_year(search_year)
    elif search_date:
        result = api.fetch.by_date(search_date)

    # file input will take precedence over a string argument if both are provided
    if input_file:
        search_objects = parse_cpe_search_file(input_file)
        result = result.filter(cpe_data__cpeMatchString__in=search_objects)
    elif search_string:
        result = api.fetch.cpe_string_contains(search_string)
        
    # a default output file name
    if not output_file:
        output_file = 'output.csv'

    print('Generating csv...')
    output_to_csv(output_file, result)

# pass the arguments into the main function when the script starts
if __name__ == "__main__":
   main(sys.argv[1:])
