#!/usr/bin/env python2
"""
Query whois information per range

Extract IPs from a file : grep -hEo '([0-9]{1,3}\.){3}[0-9]{1,3}' file
"""

from __future__ import print_function
import sys, subprocess, re, os.path


try:
    from netaddr import iprange_to_cidrs, IPAddress
except ImportError:
    print('get netaddr package on https://pypi.python.org/pypi/netaddr/')
    sys.exit(1)


DEBUG = True
WHOIS_ENTRIES = {'netnum': ('netnum', 'inetnum', 'netrange', 'inetrange'),\
    'netname': ('netname', 'inetname'),\
    'description': ('description', 'descr')}


def _parse_whois_response(lines):
    """
    Extract info from a whois response
    """
    # use a decremental state so that we do not forget to update check when
    # adding a new entry :)
    state = len(WHOIS_ENTRIES.keys())
    rslt = {}
    for key in WHOIS_ENTRIES.keys():
        rslt[key] = None
    for line in lines:
        if state == 0:
            break
        for fieldtype, fieldnamelist in WHOIS_ENTRIES.items():
            for fieldname in fieldnamelist:
                fieldnamelen = len(fieldname)
                cmp1 = '%s:' % (line[:fieldnamelen].lower())
                cmp2 = '%s:' % (fieldname.lower())
                if cmp1 == cmp2:
                    val = line.split(':', 2)[1].strip()
                    if rslt[fieldtype] == None:
                        rslt[fieldtype] = val
                        state -= 1
    # this comes out not ordered as we expect :(
    #return tuple(rslt.values)
    return (rslt['netnum'], rslt['netname'], rslt['description'])


def do_whois_query(ipaddr):
    """
    perform a whois request per ip/ip range and give bash information in the
    specified field
    """
    proc = subprocess.Popen(['whois', ipaddr], stdout=subprocess.PIPE,\
        stderr=subprocess.STDOUT)
    rslt = proc.communicate()[0]
    if proc.returncode == 0:
        if DEBUG:
            outfile = open('/tmp/whois-%s' % (ipaddr), 'w')
            outfile.write(rslt)
            outfile.close()
        lines = rslt.split('\n')
        return _parse_whois_response(lines)
    return (None, None, None)


def _is_non_routable(ipaddr):
    """
    Return True if ipaddr is private, locallink, loopback, reserved or multicast
    """
    if ipaddr.is_private() or ipaddr.is_link_local() or ipaddr.is_loopback() \
        or ipaddr.is_multicast() or ipaddr.is_reserved():
        return True
    return False

def _get_ip_addr(ipstr):
    """
    clean-up IP string address and return a IPAddress object
    """
    ipstr = ipstr.strip()
    # some addresses are interpreted as octal !
    ipstr = re.sub(r'\.0([1-9]+)', r'.\1', ipstr)
    return IPAddress(ipstr)


def _get_ip_range(rangestr):
    """
    clean-up range and return a IPRange object
    """
    start, stop = rangestr.split('-', 2)
    start = start.strip()
    stop = stop.strip()
    iprange = iprange_to_cidrs(start, stop)[0]
    return iprange


def main(filename):
    """
    main
    """
    iplist = open(filename, 'r').readlines()
    iprangelist = []
    for ipstr in iplist:
        ipaddr = _get_ip_addr(ipstr)
        if _is_non_routable(ipaddr):
            continue
        # Have we seen such a range ?
        done = False
        for iprangeobj in iprangelist:
            if ipaddr in iprangeobj:
                done = True
                break
        if done == True:
            continue
        # pylint: disable=unbalanced-tuple-unpacking
        inetnum, inetname, description = do_whois_query(str(ipaddr))
        if inetnum == None or inetname == None:
            print('-E- Invalid iprange or inetname for ip %s' % str(ipaddr))
            continue
        iprange = _get_ip_range(inetnum)
        iprangelist.append(iprange)
        sys.stdout.write('%s: %s' % (str(iprange), inetname))
        if description != None:
            print(' (%s)' % description)
        else:
            print('')


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("""syntax: %s file0 [file1...]

Takes a list of IP and perform whois request only if this IP address does not
belong to an already checked range.

Can be useful to check ACLs or FW rules allowed incoming IPs.
""" % (os.path.basename(sys.argv[0])))
        sys.exit(0)
    for thefilename in sys.argv[1:]:
        main(thefilename)

# vim: tw=80 et sw=4 ts=4
