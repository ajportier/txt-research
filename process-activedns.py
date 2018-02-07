#!/usr/bin/env python

import sys
import glob
import os
import re
import datetime
import json
import fastavro as avro

basedir = '/home/aportier/activedns-scripts'
topfile = basedir + '/top-1m.csv'
outdir = basedir + '/json'
filelist = glob.glob(os.getcwd() + "/*.avro")
filelist.sort()

for infile in filelist:
    filenum = re.search('(\d+)\.avro', infile).group(1)
    outfile = outdir + '/{}.json'.format(filenum)

    if (os.path.isfile(outfile) == False):
        output = open(outfile, 'w')
        sys.stdout.write("Processing {}\n".format(infile))
        start = datetime.datetime.now()
        with open(infile, 'rb') as i:
            reader = avro.reader(i)
            schema = reader.schema

            for record in reader:
                if (record['qtype'] == 16):
                    output.write("{}\n".format(json.dumps(record)))

        output.close()
        end = datetime.datetime.now()
        delta = end - start
        sys.stdout.write("Took {} seconds\n".format(delta.total_seconds()))

    else:
        sys.stdout.write('Skipping {}; already processed\n'.format(infile))
