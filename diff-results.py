#!/usr/bin/env python
# Author: Adam Portier <aporti01@villanova.edu>
# Date: November 7, 2017
# diff-results.py: Simple script to identify all the differences between 2 classified json
#   data sets


import sys
import re
import json
import argparse


def diffSet(set1, set2):

    diff_set = { 'changed' : {}, 'missing' : {} }

    for key in set1.keys():
        for record in set1[key]['records']:
            try:
                if (record not in set2[key]['records']):
                    #sys.stdout.write('{}\n'.format(record))

                    (rrset, rdata) = splitRecord(record)
                    set1count = countOccurances(rrset, set1[key]['records'])
                    set2count = countOccurances(rrset, set2[key]['records'])

                    # If the record isn't in set 2 and there are fewer records, its gone
                    if (set2count < set1count):
                        try:
                            diff_set['missing'][key]['records'].append(record)
                            diff_set['missing'][key]['count'] += 1
                        except KeyError:
                            diff_set['missing'][key] = {}
                            diff_set['missing'][key]['records'] = [record]
                            diff_set['missing'][key]['count'] = 1

                    # If the record isn't in set 2 and the record count is the same, it changed
                    elif (set2count == set1count):
                        try:
                            diff_set['changed'][key]['records'].append(record)
                            diff_set['changed'][key]['count'] += 1
                        except KeyError:
                            diff_set['changed'][key] = {}
                            diff_set['changed'][key]['records'] = [record]
                            diff_set['changed'][key]['count'] = 1

                    
            except KeyError:
                #sys.stdout.write('{}\n'.format(record))
                try:
                    diff_set['missing'][key]['records'].append(record)
                    diff_set['missing'][key]['count'] += 1
                except KeyError:
                    diff_set['missing'][key] = {}
                    diff_set['missing'][key]['records'] = [record]
                    diff_set['missing'][key]['count'] = 1

    for key in set2.keys():
        for record in set2[key]['records']:
            try:
                if (record not in set2[key]['records']):

                    (rrset, rdata) = splitRecord(record)
                    set1count = countOccurances(rrset, set1[key]['records'])
                    set2count = countOccurances(rrset, set2[key]['records'])

                    # If the record isn't in set 2 and the record count increased, it's new
                    if (set2count > set1count):
                        try:
                            diff_set['new'][key]['records'].append(record)
                            diff_set['new'][key]['count'] += 1
                        except KeyError:
                            diff_set['new'][key] = {}
                            diff_set['new'][key]['records'] = [record]
                            diff_set['new'][key]['count'] = 1


            except KeyError:
                try:
                    diff_set['new'][key]['records'].append(record)
                    diff_set['new'][key]['count'] += 1
                except KeyError:
                    diff_set['new'][key] = {}
                    diff_set['new'][key]['records'] = [record]
                    diff_set['new'][key]['count'] = 1

    return diff_set


def splitRecord(record):
    rparts = record.split()
    rrset = rparts[0]
    rdata = ' '.join(rparts[1:])
    return (rrset, rdata)


def countOccurances(rrset, records):
    count = 0
    for record in records:
        if record.startswith(rrset):
            count += 1

    return count


def main():
    set1 = {}
    set2 = {}

    parser = argparse.ArgumentParser(description="Identify differences between two result sets")
    parser.add_argument('set1', type=str)
    parser.add_argument('set2', type=str)
    parser.add_argument('output', type=str)
    args = parser.parse_args()
    set1file = args.set1
    set2file = args.set2
    output = args.output

    with open(set1file, 'r') as f:
        set1 = json.load(f)

    with open(set2file, 'r') as f:
        set2 = json.load(f)

    diff_set = diffSet(set1, set2)

    if (diff_set['missing'].keys() > 0):
        sys.stdout.write("----- MISSING -----\n")
        for key in diff_set['missing'].keys():
            sys.stdout.write("{} {}\n".format(key, diff_set['missing'][key]['count']))

    if (diff_set['changed'].keys() > 0):
        sys.stdout.write("----- CHANGED -----\n")
        for key in diff_set['changed'].keys():
            sys.stdout.write("{} {}\n".format(key, diff_set['changed'][key]['count']))

    with open(output, 'w') as f:
        f.write("{}\n".format(json.dumps(diff_set, indent=4, sort_keys=True)))
    f.close()


if __name__ == '__main__': main()
