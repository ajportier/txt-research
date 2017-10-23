#!/usr/bin/env python
# Author: Adam Portier <aporti01@villanova.edu>
# Date: October 23, 2017
# get-txt-records.py: Processes a list of rrsets (one per line) and outputs a list of the
#   rrsets that contain at least one TXT record
#   INPUT: Text file list of rrsets, one rrset per line
#   OUTPUT: Text file list of rrsets with at least 1 TXT record, one rrset per line

import sys
import time
from dns.resolver import *

from dns_audit import *

LOCAL_RESOLVER = dns.resolver.Resolver()

LOCAL_DNS_ADDR = ['127.0.0.1']
LOCAL_DNS_PORT = 53
REPORT_FILE = 'report.txt'
ERROR_FILE = 'error.log'


def parseRecord(record, out_f):

    queries = 0
    max_queries = 10
    starttime = time.time()

    try:
        answers = lookupTxtRecord(record, LOCAL_RESOLVER)

        if (len(answers) > 0):
            out_f.write("{}\n".format(record))

        # Really simple attempt at a 20 QPS throttle
        queries += 1
        timediff = int(time.time() - starttime)

        if queries == max_queries:
            starttime = time.time()
            queries = 0
            time.sleep(1)

        if (timediff >= 2):
            queries = 0
            starttime = time.time()

    except Exception as e:
        with open(ERROR_FILE, 'w') as f:
            f.write("{}\n".format(record)) 


def main():
    parser = argparse.ArgumentParser(description="Given a list of DNS rrsets, produces a list of rrsets with at least 1 TXT record")
    parser.add_argument('input', type=str)
    parser.add_argument('output', type=str)
    args = parser.parse_args()
    records_file = args.input
    REPORT_FILE = args.output

    in_f = open(records_file, 'rb')
    out_f = open(REPORT_FILE, 'w')

    LOCAL_RESOLVER.nameservers = LOCAL_DNS_ADDR
    LOCAL_RESOLVER.port = LOCAL_DNS_PORT

    for line in in_f:
        record = line.rstrip()
        parseRecord(record, out_f)

    in_f.close()
    out_f.close()

if __name__ == '__main__': main()
