# txt-research
Source code for my DNS TXT research project

## Setup
This project requires the dnspython and netaddr Python libraries, you can install from your package manager's repository or use the included requirements.txt file. The project also assumes that you are running a local DNS server for resolution answering on 127.0.0.1 UDP port 53

## Workflow (ActiveDNS)
1. Obtain record dump from ActiveDNS
1. **process-activedns.py <activedns_dir>** to do first-pass process from avro to json
1. **activedns-rank-json.py <activedns_json_dir>** to create unified json file in order of Cisco top domains rank
1. **domain-record-format.py <activedns_json_file>** to reduce size of unified list and change format to work with classifier
1. **classify.py <txt-records.txt> <records.json>** to run classifier on reduced record list
    1. **remove-class.py <records.json> <txt-records.txt>** to remove the classification of the records and revert to a list

## How to Use (manual fetch) (OLD)
1. Obtain a list of resource record sets (rrsets), one set per line
1. **get-txt-rrsets.py <input.txt> <txt-rrsets.txt>** to obtain a list of just the rrsets with at least one TXT record
1. **get-txt-records.py <txt-rrsets.txt> <txt-records.txt>** to obtain all the records for the list of TXT rrsets
1. **classify.py <txt-records.txt> <records.json>** to classify all the obtained records into groups and export a JSON object
1. Perform additional analysis on the classified records in the JSON output
    1. **remove-class.py <records.json> <txt-records.txt>** removes the classification of the records and reverts to a list
