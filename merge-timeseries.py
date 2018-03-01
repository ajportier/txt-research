#!/usr/bin/env python
# Author: Adam Portier <aporti01@villanova.edu>
# Date: November 7, 2017
# diff-results.py: Simple script to identify all the differences between 2 classified json
#   data sets


import sys
import glob
import os
import re
import json
import pprint


def parseFile(infile):
    data = json.load(open(infile))
    return_data = {}
    for rtype in data.keys():
        for record in data[rtype]['records']:
            parts = record.split()
            domain = parts[0]
            rrdata = ' '.join(parts[1:])

            try:
                return_data[domain][rtype]['count'] += 1
                return_data[domain][rtype]['records'].append(rrdata)
            except KeyError:

                if domain not in return_data.keys():
                    return_data[domain] = {}
                
                return_data[domain][rtype] = {'count': 1, 'records': [rrdata]}

    return return_data


def main():
    
    merged_results = {}

    output_file = 'merged.json'

    filelist = glob.glob(os.getcwd() + "/*-class.json")
    filelist.sort()

    for infile in filelist:
        sampledate = re.search('activedns\-([0-9]+)\-class.json', infile).group(1)
        sys.stdout.write("Processing capture for {}\n".format(sampledate))
        sample_data = parseFile(infile)

        for domain in sample_data.keys():

            if domain not in merged_results.keys():
                merged_results[domain] = {}


            for rtype in sample_data[domain].keys():
                if rtype not in merged_results[domain].keys():
                    merged_results[domain][rtype] = {}

                merged_results[domain][rtype][sampledate] = sample_data[domain][rtype]


    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(merged_results)

    with open(output_file, 'w') as f:
        f.write("{}\n".format(json.dumps(merged_results, indent=4, sort_keys=True)))
    f.close()



if __name__ == '__main__': main()
