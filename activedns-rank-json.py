#!/usr/bin/env python
# Author: Adam Portier <aporti01@villanova.edu>
# Date: December 19, 2017
# activedns-rank-json.py: Takes in a directory of JSON formatted ActiveDNS records and matches them to a CSV list of
#   domains and ranks. Outputs a single file of all the records appearing in the ranking, sorted by rank.

import sys
import glob
import os
import re
import json
import argparse
import fastavro as avro


def buildTopdomains(topfile):
    topdomains = {}
    sys.stdout.write("Reading top 1 million domains into memory\n")
    with open(topfile, 'r') as f:
        for line in f.readlines():
            line = line.strip()
            parts = line.split(',')
            rank = parts[0]
            domain = parts[1]

            if not(domain.endswith('.')):
                domain += '.'

            topdomains[domain] = rank

    return topdomains


def processJsonFile(topdomains, infile):
    with open(infile, 'r') as f:
        sys.stdout.write("Processing {}\n".format(infile))
        for line in f.readlines():
            line = line.strip()
            record = json.loads(line)
            qname = record['qname']

            try:
                rank = topdomains[qname]
                record['rank'] = rank
                yield(record)
            except KeyError:
                pass


def main():

    parser = argparse.ArgumentParser(description="Processes a directory of JSON formatted ActiveDNS records into a single ranked file")
    parser.add_argument('indir', type=str)
    args = parser.parse_args()

    basedir = os.getcwd()
    topfile = basedir + '/top-1m.csv'
    filelist = glob.glob(args.indir + "/*.json")
    outfile = basedir + '/output.json'

    topdomains = buildTopdomains(topfile)

    records = []

    for infile in filelist:
        for record in processJsonFile(topdomains, infile):
            records.append(record)

    sys.stdout.write("Sorting {} Records...\n".format(len(records)))
    sorted_records = sorted(records, key=lambda k: int(k['rank']))

    with open(outfile, 'w') as o:
        for record in sorted_records:
            o.write("{}\n".format(json.dumps(record)))


if __name__ == '__main__': main()
