# txt-research
Source code for my DNS TXT research project

## Setup
This project requires the dnspython and netaddr Python libraries, you can install from your package manager's repository or use the included requirements.txt file
The project also assumes that you are running a local DNS server for resolution answering on 127.0.0.1 UDP port 53

## How to Use
1. Obtain a list of resource record sets (rrsets), one set per line
1. **get-txt-rrsets.py <input.txt> <txt-rrsets.txt>** to obtain a list of just the rrsets with at least one TXT record
1. **get-txt-records.py <txt-rrsets.txt> <txt-records.txt>** to obtain all the records for the list of TXT rrsets
1. **classify.py <txt-records.txt> <records.json>** to classify all the obtained records into groups and export a JSON object
1. Perform additional analysis on the classified records in the JSON output
    1. **remove-class.py <records.json> <txt-records.txt>** removes the classification of the records and reverts to a list
