#!/usr/bin/env python
# Author: Adam Portier <aporti01@villanova.edu>
# Date: October 23, 2017
# get-txt-records.py: Processes a list of rrsets containing at least 1 TXT record (one rrset
#   per line) and outputs a list of the rrsets in "domain rrdata" format
#   INPUT: Text file list of rrsets with at least 1 TXT record, one rrset per line
#   OUTPUT: Text file list of records, one record per line, in "domain rrdata" format

import sys
import json
import argparse
from dns.resolver import *

from dns_audit import *

LOCAL_RESOLVER = dns.resolver.Resolver()
LOCAL_DNS_ADDR = ['127.0.0.1']
LOCAL_DNS_PORT = 53
ERROR_FILE = 'error.log'


def parseRecord(record, report_file):

    try:
    	answers = lookupTxtRecord(record, LOCAL_RESOLVER)

        if (len(answers) > 0):
            for answer in answers:
                record_answer = '{} {}'.format(record, answer)
            with open(report_file, 'a+') as f:
		f.write("{}\n".format(record_answer))            

    except Exception:
        with open(ERROR_FILE, 'a+') as f:
            f.write("{}\n".format(record))
        f.close()


def main():
    records = []

    parser = argparse.ArgumentParser(description="Given a list of rrsets containing at least one TXT record, generates a list of all records")
    parser.add_argument('input', type=str)
    parser.add_argument('output', type=str)
    args = parser.parse_args()
    records_file = args.input
    report_file = args.output

    with open(records_file, 'rb') as f:
        records = f.readlines()
    f.close()
    records = [x.rstrip() for x in records]

    LOCAL_RESOLVER.nameservers = LOCAL_DNS_ADDR
    LOCAL_RESOLVER.port = LOCAL_DNS_PORT

    for record in records:
        parseRecord(record, report_file)


if __name__ == '__main__': main()
