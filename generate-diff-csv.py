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
            master_dict[daterange][rtype] = new_dict[rtype]
        except KeyError:
            master_dict[daterange] = {}
            master_dict[daterange][rtype] = new_dict[rtype]

    return master_dict


def generateRtypes(data):
    rtypes = []
    for date in data.keys():
        for rtype in data[date].keys():
            if rtype not in rtypes:
                rtypes.append(rtype)

    return rtypes


def outputFile(data, dates, header, ftype):

    filename = ftype + '.csv'
    with open(filename, 'w') as o:
        o.write('date,' + ','.join(header) + '\n')
        for date in dates:
            line = date
            for rtype in header:
                try:
                    line += ",{}".format(data[date][rtype])
                except KeyError:
                    line += ",0"

            o.write(line + '\n')


def main():
    filelist = glob.glob(os.getcwd() + "/*.json")
    filelist.sort()
   
    new_counts = {}
    changed_counts = {}
    missing_counts = {}

    dates = []

    for infile in filelist:
        daterange = re.search('diff\-([0-9\-]+)\.json', infile).group(1)
        enddate = re.search('\-([0-9]+)', daterange).group(1)
        dates.append(enddate)
        fnew = readFile(infile, 'new')
        fchanged = readFile(infile, 'changed')
        fmissing = readFile(infile, 'missing')

        new_counts = mergeDicts(new_counts, fnew, enddate)
        changed_counts = mergeDicts(changed_counts, fchanged, enddate)
        missing_counts = mergeDicts(missing_counts, fmissing, enddate)


    new_types = generateRtypes(new_counts)
    changed_types = generateRtypes(changed_counts)
    missing_types = generateRtypes(missing_counts)

    outputFile(new_counts, dates, new_types, 'new')
    outputFile(changed_counts, dates, changed_types, 'changed')
    outputFile(missing_counts, dates, missing_types, 'missing')
    


if __name__ == '__main__': main()
