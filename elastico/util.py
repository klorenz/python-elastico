import sys

if (sys.version_info > (3, 0)):
    PY3 = True
else:
    PY3 = False

from datetime import datetime,date
from dateutil.parser import parse as dt_parse

def dt_isoformat(dt, sep='T', timespec='seconds'):
    if not isinstance(dt, (datetime, date)):
        dt = dt_parse(dt)

    if PY3:
        result = dt.isoformat(sep, timespec)
        result = result.rsplit('+', 1)[0]

    else:
        result = dt.isoformat(sep)
        result = result.rsplit('+', 1)[0]

        print("result: %s" % result)
        if timespec == 'hours':
            result = result.split(':')[0]
        elif timespec == 'minutes':
            result = result.rsplit(':', 1)[0]
        elif timespec == 'seconds':
            if '.' in result:
                result = result.rsplit('.', 1)[0]
        else:
            raise Exception("timespec %s not supported", timespec)
        print("result2: %s" % result)

    return result+"Z"

def to_dt(x):
    if isinstance(x, datetime):
        return x
    return dt_parse(x)

def get_netrc_login_data(data, name):
    """
    raises LookupError, in case "name" not in "data"
    :returns:
    """
    # netrc configuration
    nrc = data.get(name, {})

    if not nrc:
        raise LookupError("no netrc data present")

    if not isinstance(nrc, dict):
        filename = None
        machine  = nrc
    else:
        filename = nrc.get('file')
        machine  = nrc.get('machine')

    if nrc:
        import netrc
        (user, account, password) = netrc.netrc(filename).authenticators(machine)

    return (user, password)
