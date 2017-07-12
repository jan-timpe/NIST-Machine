from api.models import VulnerabilityVector
import api.vulnerability_database as api
from datetime import datetime, timedelta
import sys, getopt

def parse_cpe_search_file(filename):
    f = open(filename, 'r')

    cpe_search_strings = []
    for line in f:
        cpe_search_strings.append(line)

    f.close()
    return cpe_search_strings

def output_to_csv(filename, vuln_vectors):
    f = open(filename, 'w')
    result = [v.as_csv_row() for v in vuln_vectors]
    f.write('\n'.join(result))
    f.close()

def die_with_usage_help():
    print('usage: main.py -i <input_file> -o <output_file> -d <days_ago> -y <year>')
    sys.exit(2)

def get_startup_options(argv):
    input_file = None
    output_file = None
    search_date = None
    search_year = None

    try:
        opts, args = getopt.getopt(argv,'rhi:d:y:o:', ['refresh', 'input=', 'output=', 'days=', 'year=', 'help'])
    except getopt.GetoptError:
        die_with_usage_help()

    for opt, arg in opts:
        if opt in ('-r', '--refresh'):
            print('refresh option')
            api.refresh_all()
        elif opt in ('-i', '--input'):
            print('input file option')
            input_file = arg
        elif opt in ('-o', '--output'):
            print('output file option')
            output_file = arg
        elif opt in ('-d', '--days'):
            print('search days option')
            delta = timedelta(**{'days': float(arg)})
            search_date = datetime.now() - delta
        elif opt in ('-y', '--year'):
            print('search year option')
            search_year = int(arg)
        elif opt in ('-h', '--help'):
            print('help option')
            die_with_usage_help()

    return (input_file, output_file, search_date, search_year)

def main(argv):
    input_file, output_file, search_date, search_year = get_startup_options(argv)

    if not input_file and not search_date and not search_year:
        print('invalid configuration')
        die_with_usage_help()

    result = None

    if search_year:
        print('year search takes priority over day search')
        result = api.fetch.by_year(search_year)
    elif search_date:
        print('day search')
        result = api.fetch.by_date(search_date)

    if input_file:
        print('input file search')
        search_strings = parse_cpe_search_file(input_file)
        result.filter(cpe_data__cpeMatchString__icontains__in=search_strings)

    if not output_file:
        print('output not specified')
        output_file = 'output.csv'

    print('generating csv')
    output_to_csv(output_file, result)

if __name__ == "__main__":
   main(sys.argv[1:])
