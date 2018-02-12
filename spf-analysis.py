#!/usr/bin/env python

import argparse
import json
import re
import sys
import netaddr
from netaddr import *

# Given an SPF TXT record, performs some analysis of the contents and returns the result
def processSpfRecord(record):
    spf_stats = {
        'catch-all':'none',
        'ip4': 0,
        'ip4_addresses': 0,
        'ip6': 0,
        'a': 0,
        'mx': 0,
        'ptr': 0,
        'exist': 0,
        'include': 0,
        'include-targets': [],
        'include-gmail': False
    }

    catch_all = False
    record_parts = record.split()
    spf_stats['domain'] = record_parts[0]
    for part in record_parts:
        # Make note of the catch-all rule
        if (part == '+all'):
            spf_stats['catch-all'] = 'pass'
            catch_all = True

        elif (part == '-all'):
            spf_stats['catch-all'] = 'fail'
            catch_all = True

        elif (part == '~all'):
            spf_stats['catch-all'] = 'soft-fail'
            catch_all = True

        elif (part == '?all'):
            spf_stats['catch-all'] = 'neutral'
            catch_all = True

        elif (part.startswith('ip4')):
            try:
                network = re.search('ip4:(.*)', part).group(1)
                spf_stats['ip4_addresses'] += IPNetwork(network).size
                spf_stats['ip4'] += 1
            except netaddr.core.AddrFormatError:
                sys.stderr.write('Error processing network {}\n'.format(network))
            except (AttributeError, ValueError):
                sys.stderr.write('Error processing ip4 directive {}\n'.format(part))

        elif (part.startswith('ip6')):
            try:
                network = re.search('ip6:(.*)', part).group(1)
                spf_stats['ip6'] += 1
        #        spf_stats['ip6_addresses'] += IPNetwork(network).size
            except netaddr.core.AddrFormatError:
                sys.stderr.write('Error processing network {}\n'.format(network))
            except (AttributeError, ValueError):
                sys.stderr.write('Error processing ip6 directive {}\n'.format(part))

        elif (part.startswith('a')):
            spf_stats['a'] += 1

        elif (part.startswith('mx')):
            spf_stats['mx'] += 1

        elif (part.startswith('exist')):
            spf_stats['exist'] += 1

        elif (part.startswith('include:')):
            target = part.split(':')[1]
            spf_stats['include'] += 1
            spf_stats['include-targets'].append(target)
            if ('include:_spf.google.com' in part):
                spf_stats['include-gmail'] = True

    return spf_stats


def main():
    parser = argparse.ArgumentParser(description="Given the JSON output of a classified result set, performs some metrics on SPF records")
    parser.add_argument('input', type=str)
    parser.add_argument('output', type=str)
    args = parser.parse_args()
    records_file = args.input
    REPORT_FILE = args.output
    
    headers = ['domain','catch-all','ip4','ip4_addresses','ip6','a','mx','ptr','exist','include','include-gmail']

    data = json.load(open(records_file))
    out_f = open(REPORT_FILE, 'w')
    out_f.write("{}\n".format(','.join(headers)))

    include_targets = {}
    top_include = []

    for record in data['spf']['records']:
        line = []
        spf_stats = processSpfRecord(record)
        for header in headers:
            line.append(spf_stats[header])
            
        for target in spf_stats['include-targets']:
            try:
                include_targets[target] += 1
            except KeyError:
                include_targets[target] = 1

        line = [str(x) for x in line]
        out_f.write("{}\n".format(','.join(line)))

    sys.stdout.write("----- Include Statement Targets -----\n")
    for key, value in sorted(include_targets.iteritems(),
            key=lambda (k,v) : (v,k), reverse=True):
        if len(top_include) < 10:
            top_include.append("{} {}".format(key, value))
        #print "%s: %s" % (key, value)

    for target in top_include:
        sys.stdout.write("{}\n".format(target))

    out_f.close()


if __name__ == '__main__': main()
