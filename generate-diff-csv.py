#!/usr/bin/env python

import sys
import glob
import os
import re
import json

def readFile(infile, category):
    data = json.load(open(infile))
    return_data = {}
    for rtype in data[category].keys():
        return_data[rtype] = data[category][rtype]['count']

    return return_data


def mergeDicts(master_dict, new_dict, daterange):
    for rtype in new_dict.keys():
        try:
            master_dict[rtype][daterange] = new_dict[rtype]
        except KeyError:
            master_dict[rtype] = {}
            master_dict[rtype][daterange] = new_dict[rtype]

    return master_dict


def outputFile(data, header, ftype):

    filename = ftype + '.csv'
    with open(filename, 'w') as o:
        o.write(',' + ','.join(header) + '\n')
        for rtype in data.keys():
            line = rtype
            for date in header:
                try:
                    line += ",{}".format(data[rtype][date])
                except KeyError:
                    line += ",0"

            o.write(line + '\n')


def main():
    filelist = glob.glob(os.getcwd() + "/*.json")
    filelist.sort()
   
    dateranges = []
    new_counts = {}
    changed_counts = {}
    missing_counts = {}

    for infile in filelist:
        daterange = re.search('diff\-([0-9\-]+)\.json', infile).group(1)
        dateranges.append(daterange)
        fnew = readFile(infile, 'new')
        fchanged = readFile(infile, 'changed')
        fmissing = readFile(infile, 'missing')

        new_counts = mergeDicts(new_counts, fnew, daterange)
        changed_counts = mergeDicts(changed_counts, fchanged, daterange)
        missing_counts = mergeDicts(missing_counts, fmissing, daterange)


    outputFile(new_counts, dateranges, 'new')
    outputFile(changed_counts, dateranges, 'changed')
    outputFile(missing_counts, dateranges, 'missing')
    


if __name__ == '__main__': main()
