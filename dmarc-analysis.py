#!/usr/bin/env python

import argparse
import json
import re
import sys
import netaddr
from netaddr import *


def main():
    parser = argparse.ArgumentParser(description="Given the JSON output of a classified result set, performs some metrics on DMARC records")
    parser.add_argument('input', type=str)
    args = parser.parse_args()
    records_file = args.input
    
    data = json.load(open(records_file))

    total = 0
    policies = {'none': 0, 'reject': 0, 'quarantine': 0, 'monitor': 0}
    return_addresses = {'rua': 0, 'ruf': 0, 'both': 0, 'neither': 0}
    other_txt = {'spf': 0, 'dkim': 0, 'both': 0, 'neither': 0}

    spf_domains = []
    for record in data['spf']['records']:
        spf_domains.append(record.split()[0])


    dkim_domains = []
    for record in data['dkim']['records']:
        dkim_domains.append(record.split()[0])



    for record in data['dmarc']['records']:
        total += 1
        record = record.replace('\\', '') # squish all the leftover escapes from jsonifying
        parts = record.split()
        domain = parts[0]
        parts = ' '.join(parts[1:]).split(';')

        found_rua = False
        found_ruf = False
        has_spf = (domain in spf_domains)
        has_dkim = (domain in dkim_domains)


        for part in parts:
            part = re.sub('\s+', '', part) # collapse whitespace

            if part.startswith('p='):
                policy = re.match('p=(.+)', part).group(1)
                policies[policy] += 1

            if part.startswith('rua='):
                found_rua = True

            if part.startswith('ruf='):
                found_ruf = True


        if (found_rua and found_ruf):
            return_addresses['both'] += 1
        elif found_rua:
            return_addresses['rua'] += 1
        elif found_ruf:
            return_addresses['ruf'] += 1
        else:
            return_addresses['neither'] += 1


        if (has_spf and has_dkim):
            other_txt['both'] += 1
        elif has_spf:
            other_txt['spf'] += 1
        elif has_dkim:
            other_txt['dkim'] += 1
        else:
            other_txt['neither'] += 1

            


    sys.stdout.write('----- DMARC Analysis -----\n')
    sys.stdout.write('Total records: {}\n'.format(total))
    sys.stdout.write('Policies\n')
    for policy in policies.keys():
        sys.stdout.write('{}: {}\n'.format(policy, policies[policy]))

    sys.stdout.write('Return Addresses\n')
    for return_address in return_addresses.keys():
        sys.stdout.write('{}: {}\n'.format(return_address, return_addresses[return_address]))

    sys.stdout.write('Other TXT Records\n')
    for txt in other_txt.keys():
        sys.stdout.write('{}: {}\n'.format(txt, other_txt[txt]))
            



if __name__ == '__main__': main()
