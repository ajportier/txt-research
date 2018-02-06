#!/usr/bin/env python

import json
import sys
import re

unique_rrsets = 10000
infile = sys.argv[1]
outfile = '{}.txt'.format(re.search('(.+)\.json', infile).group(1))

records = []
rrsets = []

with open(infile, 'r') as f:
    for line in f.readlines():
        if (len(rrsets) < unique_rrsets):
            line = line.strip()
            record = json.loads(line)
            qname = record['qname']
            rdata = record['rdata']
            records.append('{} {}'.format(qname, rdata))
            if (qname not in rrsets):
                rrsets.append(qname)

sys.stdout.write("Found {} records across {} unique rrsets\n".format(len(records), len(rrsets)))

with open(outfile, 'w') as o:
    for record in records:
        o.write('{}\n'.format(record))
