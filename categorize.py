#!/usr/bin/env python

import sys
import re

PROTOCOL_ENHANCEMENT = [
        'spf',
        'base64',
        'sender-id',
        'dkim',
        'dmarc'
        ]

DOMAIN_VERIFICATION = [
        'google-site-verification',
        'office365ms',
        'amazonses',
        'salesforce-pardot',
        'yandex-verification',
        'outlookmsv1',
        'office365verifydomain',
        'sendinblue-code',
        'zoho-verification',
        'mailru-domain',
        'wmail-verification',
        'globalsign-domain-verification',
        'dzc',
        'dropbox-domain-verification',
        'cisco-ci-domain-verification',
        'logmein-openvoice',
        'status-page-domain-verification',
        'firebase',
        'workplace-domain-verification',
        'postman-domain-verification',
        'cloudcontrol',
        'adobe-idp-site-verification',
        'atlassian-domain-verification',
        'citrix-verification-code',
        'bugcrowd-verification',
        'logmein-domain-confirmation',
        'favro-verification',
        'facebook-domain-verification',
        'docusign',
        'adobe-sign-verification',
        'keybase-site-verification',
        'loaderio',
        'blitz',
        'detectify-verification',
        'have-i-been-pwned-verification',
        'tinfoil-site-verification',
        'botify-site-verification',
        'spycloud-domain-verification',
        'cloudpiercer-verification',
        'cisco-site-verification',
        'brave-ledger-verification',
        'dailymotion-domain-verification'
        ]

RESOURCE_LOCATION = [
        'symantec-mdm',
        'ivanti-landesk',
        'fuserserver',
        'bittorrent'
        ]


def main():
    input_file = sys.argv[1]
    
    counts = {'protocol_enhancement': 0.0,
            'domain_verification': 0.0,
            'resource_location': 0.0,
            'unknown': 0.0,
            'total': 0.0,
            }



    with open(input_file, 'r') as f:
        for result in f:
            result = result.rstrip()

            parts = result.split()
            count = float(parts[0])
            ident = parts[1]
            ident = re.sub('\"', '' , ident)
            found = False

            if ident in PROTOCOL_ENHANCEMENT:
                found = True
                counts['protocol_enhancement'] += count

            if ident in DOMAIN_VERIFICATION:
                found = True
                counts['domain_verification'] += count

            if ident in RESOURCE_LOCATION:
                found = True
                counts['resource_location'] += count

            if not found:
                counts['unknown'] += count

            counts['total'] += count


        for category in sorted(counts.keys()):
            perc = round(((counts[category] / counts['total']) * 100), 2)
            sys.stdout.write('{} {} {}%\n'.format(category, int(counts[category]), perc))

if __name__ == '__main__': main()
