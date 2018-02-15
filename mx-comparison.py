#!/usr/bin/env python

import argparse
import json
import re
import sys
import netaddr


def main():
    parser = argparse.ArgumentParser(description="Given the JSON output of a classified result set and a list of MX records, performs some analysis of the unified set")
    parser.add_argument('input', type=str)
    parser.add_argument('mxfile', type=str)
    args = parser.parse_args()
    records_file = args.input
    mxfile = args.mxfile
    
    data = json.load(open(records_file))

    mxdomains = []
    spfdomains = []

    with open(mxfile, 'r') as f:
        for line in f.readlines():
            domain = line.split()[0]
            if domain not in mxdomains:
                mxdomains.append(domain)


    for record in data['spf']['records']:
        domain = record.split()[0]
        if domain not in spfdomains:
            spfdomains.append(domain)

    
    spf_with_mx = 0

    for domain in spfdomains:
        if domain in mxdomains:
            spf_with_mx += 1

    sys.stdout.write('Total MX Domains: {}\n'.format(len(mxdomains)))
    sys.stdout.write('Total SPF with MX: {}\n'.format(spf_with_mx))


if __name__ == '__main__': main()
