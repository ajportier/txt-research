#!/usr/bin/env python

import argparse
import json
import re
import sys
import netaddr
from netaddr import *

# Given a SenderID TXT record, performs some analysis of the contents and returns the result
def processSenderId(record):
    senderid_stats = {
        'domain' : '',
        'pra': False,
        'mfrom': False,
        'both': False
    }

    record_parts = record.split()
    senderid_stats['domain'] = record_parts[0]
    prefix = record_parts[1]
    scopes = prefix.split('/')[1].split(',')

    if 'pra' in scopes:
        senderid_stats['pra'] = True
    if 'mfrom' in scopes:
        senderid_stats['mfrom'] = True

    if (senderid_stats['pra'] and senderid_stats['mfrom']):
        senderid_stats['pra'] = False
        senderid_stats['mfrom'] = False
        senderid_stats['both'] = True

    return senderid_stats


def main():
    parser = argparse.ArgumentParser(description="Given the JSON output of a classified result set, performs some metrics on SenderID records")
    parser.add_argument('input', type=str)
    parser.add_argument('output', type=str)
    args = parser.parse_args()
    records_file = args.input
    REPORT_FILE = args.output
    
    headers = ['domain','pra','mfrom','both']

    data = json.load(open(records_file))
    out_f = open(REPORT_FILE, 'w')
    out_f.write("{}\n".format(','.join(headers)))

    include_targets = {}
    top_include = []

    for record in data['sender-id']['records']:
        line = []
        senderid_stats = processSenderId(record)
        for header in headers:
            line.append(senderid_stats[header])
            
        line = [str(x) for x in line]
        out_f.write("{}\n".format(','.join(line)))

    out_f.close()


if __name__ == '__main__': main()
