#!/usr/bin/env python

import json
import sys
import re

top10kdomains = '/Users/aportier/git/txt-research/top-10k-txt-domains.txt'

unique_rrsets = 10000
infile = sys.argv[1]
outfile = '{}.txt'.format(re.search('(.+)\.json', infile).group(1))
mxfile = '{}-mx.txt'.format(re.search('(.+)\.json', infile).group(1))

records = []
rrsets = []

mxrecords = []

topdomains = []

with open(top10kdomains, 'r') as o:
    for line in o.readlines():
        line = line.strip()
        topdomains.append(line)

with open(infile, 'r') as f:
    for line in f.readlines():
        line = line.strip()
        record = json.loads(line)
        qname = record['qname']
        rdata = record['rdata']
        qtype = record['qtype']

        if (len(rrsets) < unique_rrsets):
        #if (qname in topdomains):

            if qtype == 16:
                records.append('{} {}'.format(qname, rdata))
                if qname not in rrsets:
                    rrsets.append(qname)

            elif qtype == 15:
                mxrecords.append('{} {}'.format(qname, rdata))


sys.stdout.write("Found {} records across {} unique rrsets\n".format(len(records), len(rrsets)))

with open(outfile, 'w') as o:
    for record in records:
        o.write('{}\n'.format(record))

with open(mxfile, 'w') as o:
    for record in mxrecords:
        o.write('{}\n'.format(record))
