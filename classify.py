#!/usr/bin/env python
# Author: Adam Portier <aporti01@villanova.edu>
# Date: October 23, 2017
# classify.py: Simple script to classify records in the .txt output of the audit scripts
#   through the classifer pattern match. This step is performed offline so records were
#   gathered once, but could be re-classified many times as the data is being analyzed.

import sys
import re
import json
import argparse

from dns_audit import *

NEW_RECORD_TYPES = {}


def parseRecord(domain, record):

    # The " " around the record were messing with the regex matches
    record = record.replace('"', '')
    domain_record = '{} {}'.format(domain, record)

    identifier = classifyTxtRecord(record)

    try:
        NEW_RECORD_TYPES[identifier]['records'].append(domain_record)
    except KeyError:
        NEW_RECORD_TYPES[identifier] = {}
        NEW_RECORD_TYPES[identifier]['records'] = [domain_record]
        NEW_RECORD_TYPES[identifier]['count'] = 0


def analyzeRecordPrefix(records):

    sys.stdout.write("----- Looking for Patterns in Unknown Records -----\n");
    disc_record_types = {}

    colon_format = re.compile('([A-Za-z0-9_/-]*:)')
    equals_format = re.compile('([A-Za-z0-9_/-]*=)')

    for record in records:
        parts = record.split()
        domain = parts[0]
        rrdata = ' '.join(parts[1:])

        if (colon_format.match(rrdata)):
            identifier = colon_format.match(rrdata).group(1)
            try:
                disc_record_types[identifier].append(domain)
            except Exception:
                disc_record_types[identifier] = [domain]

        if (equals_format.match(rrdata)):
            identifier = equals_format.match(rrdata).group(1)
            if identifier == 'k=':
                sys.stdout.write("{} {}\n".format(domain, rrdata))
            try:
                disc_record_types[identifier].append(domain)
            except Exception:
                disc_record_types[identifier] = [domain]


    for key in disc_record_types.keys():
        domain_count = len(set(disc_record_types[key]))
        disc_record_types[key] = domain_count

    sorted_record_types = sorted(disc_record_types.items(), key=lambda x: x[1])

    for (record_type, records) in sorted_record_types:
        if (records > 1):
            sys.stdout.write("{} {}\n".format(record_type, records))

    sys.stdout.write("----------\n");


def main():
    total_records = 0

    parser = argparse.ArgumentParser(description="Classify a list of records into JSON format of classified groups")
    parser.add_argument('input', type=str)
    parser.add_argument('output', type=str)
    args = parser.parse_args()
    input_file = args.input
    output_file = args.output

    with open(input_file, 'r') as f:
        for domain_record in f:
            parts = domain_record.split()
            domain = parts[0]
            rrdata = ' '.join(parts[1:])
            parseRecord(domain, rrdata)
            total_records += 1

    for key in NEW_RECORD_TYPES.keys():
        if (key != 'none'):
            NEW_RECORD_TYPES[key]['count'] = len(NEW_RECORD_TYPES[key]['records'])
            sys.stdout.write('{} {}\n'.format(key, NEW_RECORD_TYPES[key]['count']))

    unknown_records = NEW_RECORD_TYPES['unknown']['records']
    analyzeRecordPrefix(unknown_records)

    with open(output_file, 'w') as f:
        f.write("{}\n".format(json.dumps(NEW_RECORD_TYPES, indent=4, sort_keys=True)))
    f.close()

    sys.stdout.write("{} Records Classified\n".format(total_records))


if __name__ == '__main__': main()
