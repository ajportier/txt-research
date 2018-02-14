#!/usr/bin/env python

import argparse
import json
import re
import sys
import netaddr
from netaddr import *


def main():
    parser = argparse.ArgumentParser(description="Given the JSON output of a classified result set, performs some metrics on DKIM records")
    parser.add_argument('input', type=str)
    args = parser.parse_args()
    records_file = args.input
    
    data = json.load(open(records_file))


    total = 0
    key_digests = {}
    key_types = {}
    services = {}

    for record in data['dkim']['records']:
        total += 1
        record = record.replace('\\', '') # squish all the leftover escapes from jsonifying
        parts = record.split(';')
        domain = parts[0]
        key_type_found = False
        for part in parts:
            part = re.sub('\s+', '', part) # collapse whitespace
            
            if part.startswith('k='):
                key_type = re.match('k=(.*)', part).group(1)
                key_type_found = True
                try:
                    key_types[key_type] += 1
                except KeyError:
                    key_types[key_type] = 1


            if part.startswith('p='):
                key = re.match('p=(.*)', part).group(1)
                try:
                    key_digests[key] += 1
                except KeyError:
                    key_digests[key] = 1


            if part.startswith('s='):
                service = re.match('s=(.*)', part).group(1)
                try:
                    services[service] += 1
                except KeyError:
                    services[service] = 1

        if not key_type_found:
            sys.stderr.write('No key type found: {}\n'.format(record))


    sys.stdout.write('----- DKIM Analysis -----\n')
    sys.stdout.write('Total Records: {}\n'.format(total))
    sys.stdout.write('Key Types\n')
    for key_type in key_types.keys():
        sys.stdout.write('{}: {}\n'.format(key_type, key_types[key_type]))

    sys.stdout.write('Services\n')
    for service in services.keys():
        sys.stdout.write('{}: {}\n'.format(service, services[service]))

    duplicate_keys = []
    for key in key_digests.keys():
        if key_digests[key] > 1:
            duplicate_keys.append(key)

    sys.stdout.write('Duplicate keys: {}\n'.format(len(duplicate_keys)))
    if (len(duplicate_keys) > 0):
        for key in duplicate_keys:
            sys.stdout.write('{} uses of key {}\n'.format(key_digests[key], key))


if __name__ == '__main__': main()
