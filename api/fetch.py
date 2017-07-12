from api.models import VulnerabilityVector
from database.development import db
import datetime
from mongoengine.queryset.visitor import Q

# retrieves a list of objects from the mongodb instance matching the passed in arguments
def many(**kwargs):
    # result = db.cve_items.find(args)
    result = VulnerabilityVector.objects(**kwargs)
    return result

# retrieves the first object from the mongodb instance matching the passed in arguments
def one(**kwargs):
    # result = db.cve_items.find_one(args)
    result = VulnerabilityVector.get(**kwargs)
    return result

# retrieves one CVE_Item given a CVE_ID (primary key)
def by_id(id):
    result = one(cve_id=id)
    return result

def by_date(start, end=datetime.datetime.now()):
    result = VulnerabilityVector.objects(
        Q(last_modified__gte=start)
        & Q(last_modified__lte=end)
    )
    return result

# accepts 1 integer argument
def by_year(year):
    start = datetime.datetime(year, 1, 1, 0, 0, 0, 0)
    end = datetime.datetime(year, 12, 31, 23, 59, 59)
    result = by_date(start, end=end)

    return result

# accepts 1 string argument
def cpe_string_contains(search_string):
    result = many(cpe_data__cpeMatchString__icontains=search_string)
    return result
