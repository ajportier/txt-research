#!/usr/bin/env python
# Author: Adam Portier <aporti01@villanova.edu>
# Date: October 23, 2017
# remove-class.py: Simple script to remove classification from classified record set (JSON)
#   INPUT: Text file containing a JSON object of classified rrset groupings
#   OUTPUT: Text file list of rrsets, one rrset per line

import sys
import re
import json
import argparse


def main():
    total_records = 0
    record_types = {}

    parser = argparse.ArgumentParser(description="Revert classified record set to unclassified list")
    parser.add_argument('input', type=str)
    parser.add_argument('output', type=str)
    args = parser.parse_args()
    input_file = args.input
    output_file = args.output

    out_f = open(output_file, 'w')

    with open(input_file, 'r') as f:
        record_types = json.load(f)

    for key in record_types.keys():
        for record in record_types[key]['records']:
            out_f.write("{}\n".format(record))
            total_records += 1

    out_f.close()
    sys.stdout.write ("Removed Classification from {} records\n".format(total_records))
            

if __name__ == '__main__': main()
