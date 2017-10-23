# Author: Adam Portier <aporti01@villanova.edu>
# Date: October 23, 2017
# dns-audit.py: Library functions to support DNS TXT record research

import re
import sys
import time

from dns.resolver import *
#from netaddr import *

NO_NAMESERVER_TIMEOUT=10
NO_NAMESERVER_MAX_TRIES=3


# Given a dnspython resolver object, trues to resolve a TXT record and returns the rrset
def lookupTxtRecord(record, resolver, tries=0):

    answers = []
    resolved = False

    try:
        answers = resolver.query(record, 'TXT')
        delta = int(answers.expiration - time.time())
        answers = [ x.to_text().lower() for x in answers ]
        sys.stdout.write("{} {} TTL {}\n".format(record, str(answers), delta))

    # NXDOMAIN
    except dns.resolver.NoAnswer:
        sys.stdout.write("No TXT records for {}\n".format(record))
        resolved = True

    # SERVFAIL
    except dns.resolver.NoNameservers:
        sys.stderr.write("NoNameserver for {}, trying in {} seconds\n".format(record, NO_NAMESERVER_TIMEOUT))
        tries += 1

        if (tries < NO_NAMESERVER_MAX_TRIES):
            time.sleep(NO_NAMESERVER_TIMEOUT)
            answers = lookupTxtRecord(record, resolver, tries)
        else:
            sys.stderr.write("Max tries {} reached trying to resolve {}\n".format(NO_NAMESERVER_MAX_TRIES, record))
            raise

    except dns.exception.Timeout:
        sys.stderr.write("Timeout reaching {}\n".format(record))
        resolved = False

    return answers


# Given an SPF TXT record, performs some analysis of the contents and returns the result
def processSpfRecord(record):
    spf_stats = {
        'catch-all':{'pass':0, 'fail':0, 'soft-fail':0, 'neutral':0, 'none': 0},
        'ip4': [],
        'ip6': [],
    }

    catch_all = False
    ip4_addresses = 0
    ip6_addresses = 0
    record_parts = record.split()
    current_domain = record_parts[0]
    for part in record_parts:
        # Make note of the catch-all rule
        if (part == '+all'):
            spf_stats['catch-all']['pass'] += 1
            catch_all = True
        elif (part == '-all'):
            spf_stats['catch-all']['fail'] += 1
            catch_all = True
        elif (part == '~all'):
            spf_stats['catch-all']['soft-fail'] += 1
            catch_all = True
        elif (part == '?all'):
            spf_stats['catch-all']['neutral'] += 1
            catch_all = True
        elif (part.startswith('ip4')):
            network = part.split(':')[1]
            ip4_addresses += IPNetwork(network).size
        elif (part.startswith('ip6')):
            network = re.search('ip6:(.*)', part).group(1)
            ip6_addresses += IPNetwork(network).size
        #else:
            #print part
     
    if not catch_all:
        spf_stats['catch-all']['none'] += 1 
    
    spf_stats['ip4'].append({current_domain: ip4_addresses})
    spf_stats['ip6'].append({current_domain: ip6_addresses})

    return spf_stats


# Given a DNS TXT record, performs a series of pattern matches and attempts to classify it
def classifyTxtRecord(record):

    # The " " around the record were messing with the regex matches
    record = record.replace('"', '')

    identifier = ""

    ##### Formal TXT Record Formats #####

    # SPF Records
    if (record.startswith('v=spf1')):
        identifier = 'spf'

    # Malformed or multi-line SPF records
    elif (record.startswith('include:') or
            record.startswith('v=spf3') or
            record.startswith('ip4:')):
        identifier = 'spf-misconfigured'

    # SenderID records
    elif (record.startswith('spf2.0/')):
        identifier = 'sender-id'

    # Malformed or multi-line SenderID records
    elif (record.startswith('v=spf2.0')):
        identifier = 'sender-id-misconfigured'

    # DKIM records
    elif (record.startswith('v=dkim1')):
        identifier = 'dkim'

    # Malformed or multi-line DKIM records
    elif (record.startswith('k=rsa')):
        identifier = 'dkim-misconfigured'

    # DMARC records
    elif (record.startswith('v=dmarc1')):
        identifier = 'dmarc'

    ##### END Formal TXT Record Formats #####

    ##### Informal TXT Record Formats #####

    #### Domain Verification ####
    
    ### Email SaaS Verification ###

    # G Suite domain verfication
    # https://support.google.com/a/answer/183895?hl=en
    elif (record.startswith('google-site-verification')):
        identifier = 'google-site-verification'

    # Office 365 domain ownership verification
    # https://support.office.microsoft.com/en-us/article/Gather-the-information-you-need-to-create-Office-365-DNS-records-77f90d4a-dc7f-4f09-8972-c1b03ea85a67
    elif (record.startswith('ms=')):
        identifier = 'ms'

    # Outlook.com domain ownership verification
    # http://www.omegaweb.com/how-to-configure-a-custom-domain-with-outlook-com/
    # https://support.office.com/en-us/article/Use-your-own-domain-in-Outlook-com-Premium-61e21366-c809-44e5-a414-9bab47110e5f?ui=en-US&rs=en-US&ad=US
    elif (record.startswith('v=msv1')):
        identifier = 'msv1'

    # Another Office 365 domain ownership verification format
    # http://www.colome.org/office-365-dns-configuration/
    elif (record.startswith('v=verifydomain')):
        identifier = 'verifydomain'

    # Amazon Simple Email Service (SES)
    # http://docs.aws.amazon.com/ses/latest/DeveloperGuide/dns-txt-records.html
    elif (record.startswith('amazonses')):
        identifier = 'amazonses'

    # Domain uses the Salesforce Pardot email marketing platform
    # http://help.pardot.com/customer/portal/articles/2128543-setting-up-tracker-subdomain-cname-
    elif (record.startswith('pardot')):
        identifier = 'salesforce-pardot'

    # Domain uses postmaster.mail.ru service for collecting mail statistics
    # https://serverfault.com/questions/767718/what-is-dns-txt-record-mailru-verification
    elif (record.startswith('mailru-verification')):
        identifier = 'mailru-verification'

    # Domain uses the Yandex platform for managing email
    # https://yandex.com/support/domain/setting/confirm.html
    elif (record.startswith('yandex-verification')):
        identifier = 'yandex-verification'

    ### END Email SaaS Verification ###

    ### SaaS Service Verification ###

    # Facebook provided collaboration service similar to Slack
    # https://fb.facebook.com/help/work/431877453687567/
    elif (record.startswith('workplace-domain-verification=')):
        identifier = 'workplace-domain-verification'

    # Have I Been Pwned only allows searches against compromised email lists if you own the
    # domain in question
    # https://haveibeenpwned.com/DomainSearch
    elif (record.startswith('have-i-been-pwned-verification=')):
        identifier = 'have-i-been-pwned-verification'

    # Domain uses GoToMeeting with Single Sign-on through AD
    # https://support.citrixonline.com/en_US/Webinar/all_files/G2W710101
    elif (record.startswith('citrix-verification-code=')):
        identifier = 'citrix-verification-code'

    # Domain uses the StatusPage outage communication / tracking tool
    # https://help.statuspage.io/knowledge_base/topics/domain-ownership
    elif (record.startswith('status-page-domain-verification=')):
        identifier = 'status-page-domain-verification'

    # Domain uses Bugcrowd for identity verification and has enabled SAML based SSO
    # for their account
    # https://docs.bugcrowd.com/v1.0/docs/single-sign-on
    elif (record.startswith('bugcrowd-verification=')):
        identifier = 'bugcrowd-verification'

    # Domain owner has included domain in Keybase's identify proof using
    # the "keybase prove dns" option
    # https://keybase.io/docs/command_line
    elif (record.startswith('keybase-site-verification=')):
        identifier = 'keybase-site-verification'

    # Domain uses Wrike for project management
    # Could not find a specific reference to what this record is used to verify
    elif (record.startswith('wrike-verification=')):
        identifier = 'wrike-verification'

    # Domain uses Sage Intacct to manage financial data
    # Could not find specific example of what this record is used to verify
    elif (record.startswith('intacct-esk=')):
        identifier = 'intacct-esk'

    ### END SaaS Service Verification ###

    ### Advertising Services ###

    # Brave Browser account verification; used to sign a domain up to recieve bitcoin payments
    # from Brave in exchange for the Brave browser blocking their advertisements 
    # https://github.com/brave-intl/publishers/blob/master/app/services/publisher_dns_record_generator.rb
    # https://brave.com/faq/#brave-payments
    elif (record.startswith('brave-ledger-verification')):
        identifier = 'brave-ledger-verification'

    ### END Advertising Services ###

    ### Developer Tools / Infrastructure ###

    # Loader.io service for automated testing of API Endpoints
    # http://support.loader.io/article/20-verifying-an-app
    elif (record.startswith('loaderio=')):
        identifier = 'loaderio'

    # Domain uses the DocuSign electronic signature service
    # https://www.docusign.com/supportdocs/ndse-admin-guide/Content/domains.htm
    elif (record.startswith('docusign=')):
        identifier = 'docusign'

    # Domain uses the Adobe Sign service to electronically sign documents
    # https://helpx.adobe.com/sign/help/domain_claiming.html
    elif (record.startswith('adobe-sign-verification=')):
        identifier = 'adobe-sign-verification'

    # Application is hosted using Firebase
    # https://firebase.google.com/docs/hosting/custom-domain
    elif (record.startswith('firebase=')):
        identifier = 'firebase'

    # Blitz load testing SaaS
    # https://www.blitz.io/
    elif (record.startswith('blitz=')):
        identifier = 'blitz'

    # Domain uses Detectify to scan for vulnerabilties
    # https://support.detectify.com/customer/en/portal/articles/2836806-verification-with-dns-txt-
    elif (record.startswith('detectify-verification=')):
        identifier = 'detectify-verification'

    # Domain uses Tinfoil Security services to scan domain for vulnerabilities
    # https://www.tinfoilsecurity.com/privacy
    elif (record.startswith('tinfoil-site-verification:')):
        identifier = 'tinfoil-site-verification'

    # Domain uses the Adobe provided SAML2 Identity Provider service
    # https://helpx.adobe.com/enterprise/help/verify-domain-ownership.html
    elif (record.startswith('adobe-idp-site-verification')):
        identifier = 'adobe-idp-site-verification'

    # Domain verification for Sophos Email gateway service
    # https://community.sophos.com/kb/en-us/124401
    # https://community.sophos.com/kb/en-us/124703
    elif (record.startswith('sophos-domain-verification=')):
        identifier = 'sophos-domain-verification'

    # Domain verification for Dropbox Business
    # https://www.dropbox.com/help/business/domain-verification-invite-enforcement
    elif (record.startswith('dropbox-domain-verification=')):
        identifier = 'dropbox-domain-verification'

    # Domain uses Atlassian Cloud services (Confluence Wiki)
    # https://confluence.atlassian.com/cloud/domain-verification-873871234.html
    elif (record.startswith('atlassian-domain-verification=')):
        identifier = 'atlassian-domain-verification'

    # Domain uses Cisco Webex conferencing
    # https://help.webex.com/docs/DOC-4860
    elif (record.startswith('cisco-ci-domain-verification=')):
        identifier = 'cisco-ci-domain-verification'

    # Domain uses LogMeIn with ADFS for Single Sign-on
    # https://secure.logmein.com/welcome/webhelp/EN/CentralUserGuide/LogMeIn/Using_ADFS_LogMeIn_Central.html
    elif (record.startswith('logmein-domain-confirmation')):
        identifier = 'logmein-domain-confirmation'
    
    # Domain uses the CloudBees Jenkins build service with SSO enabled
    # https://docs.secureauth.com/display/CAD/Cloudbees
    elif (record.startswith('cloudbees-domain-verification:')):
        identifier = 'cloudbees-domain-verification'

    # Domain uses Moxtra for collaboration with SSO enabled
    # https://support.bitium.com/administration/saml-moxtra/
    elif (record.startswith('moxtra-site-verification=')):
        identifier = 'moxtra-site-verification'

    # Domain uses Cisco Spark services for calls and collaboration
    # https://help.webex.com/docs/DOC-4860
    elif (record.startswith('ciscocidomainverification=')):
        identifier = 'ciscocidomainverification'

    # Domain hosts videos on Dailymotion and has verified ownership so it can monitize them
    # https://faq.dailymotion.com/hc/en-us/articles/211458338-Verification-Methods
    elif (record.startswith('dailymotion-domain-verification=')):
        identifier = 'dailymotion-domain-verification'

    # Domain uses Botify to crawl their websites (SEO)
    # https://www.botify.com/support/site-validation/
    elif (record.startswith('botify-site-verification=')):
        identifier = 'botify-site-verification'

    ### END Developer Tools / Infrastructure ###

    ### SSL Certificates ###

    # GoDaddy SSL Certificate Domain Verification
    # https://www.godaddy.com/community/SSL-And-Security/SSL-Domain-Verification-with-DNS/m-p/42641#M378
    elif (record.startswith('dzc=')):
        identifier = 'dzc'

    # Domain verification for GlobalSign SSL Certificates service
    # https://support.globalsign.com/customer/portal/articles/2167245-performing-domain-verification---dns-txt-record
    elif (record.startswith('globalsign-domain-verification') or
            record.startswith('_globalsign-domain-verification=')):
        identifier = 'globalsign-domain-verification'

    ### END SSL Certificates ###

    #### END Domain Verification ####

    #### Service Location ####

    # Location of Fuse ESB message routing service
    # https://developers.redhat.com/products/fuse/overview/?referrer=jbd
    elif (record.startswith('fuseserver=')):
        identifier = 'fuserserver'

    # Domain uses Symantec Mobile Management to identify / protect mobile devices on
    # their network. This is the iOS agent string to find the enrollment server.
    # https://support.symantec.com/en_US/article.HOWTO77270.html
    elif (record.startswith('osiagentregurl=')):
        identifier = 'osiagentregurl'

    # This is the agent string for Android for Symantec Mobile Management
    elif (record.startswith('android-mdm-enroll=')):
        identifier = 'android-mdm-enroll'

    # Bittorrent Tracker Preferences
    # http://www.bittorrent.org/beps/bep_0034.html
    elif (record.startswith('bittorrent')):
        identifier = 'bittorrent'

    #### END Service Location ####

    ##### More General / Tail Matches #####

    elif (record.startswith('pod=')):
        identifier = 'pod'

    elif (record.startswith('mailru-domain:')):
        identifier = 'mailru-domain'

    elif (record.startswith('wmail-verification:')):
        identifier = 'wmail-verification'

    elif (record.startswith('zoho-verification=')):
        identifier = 'zoho-verification'

    elif (record.startswith('sendinblue-code:')):
        identifier = 'sendinblue-code'

    elif (record.startswith('cloudpiercer-verification=')):
        identifier = 'cloudpiercer-verification'

    elif (record.startswith('postman-domain-verification=')):
        identifier = 'postman-domain-verification'

    elif (record.startswith('ha:')):
        identifier = 'ha'

    elif (record.startswith('appid=')):
        identifier = 'appid'

    elif (record.startswith('i=')):
        identifier = 'i'

    elif (record.startswith('spycloud-domain-verification=')):
        identifier = 'spycloud-domain-verification'

    elif (record.startswith('favro-verification=')):
        identifier = 'favro-verification'

    elif (record.startswith('cisco-site-verification=')):
        identifier = 'cisco-site-verification='

    elif (record.startswith('ad=')):
        identifier = 'ad'

    elif (record.startswith('worksmobile-certification=')):
        identifier = 'worksmobile-certification'

    elif (record.startswith('value:')):
        identifier = 'value'

    elif (record.startswith('count=')):
        identifier = 'count'

    elif (record.startswith('citirix-verification-code=')):
        identifier = 'citirix-verification-code'

    elif (record.startswith('www=')):
        identifier = 'www'

    elif (record.startswith('p=')):
        identifier = 'p'

    elif (record.startswith('thousandeyes:')):
        identifier = 'thousandeyes'

    elif (record.startswith('as=')):
        identifier = 'as'

    elif (record.startswith('wp-noop:')):
        identifier = 'wp-noop'

    # I have no idea what these are for, no documentation on digicert's public site
    elif ('digicert order #' in record):
        identifier = 'digicert'

    elif (re.match('^\d\|[09a-z.-]+$', record)):
        identifier = 'numbered-urls'

    # Regex match for hex that is also not an integer string
    elif ((re.match('^[0-9a-f]+$', record)) and not (re.match('^[0-9]+$', record))):
        identifier = 'hexadecimal'

    # Regex match for just integer strings
    elif ((re.match('^[0-9]+$', record))):
        identifier = 'numeric'
    
    # Regex match for base64 encoded data
    # Possibly Exchange Federation keys
    # http://www.expta.com/2011/07/how-to-configure-exchange-2010-sp1.html
    # https://technet.microsoft.com/en-us/library/dd335047.aspx
    elif (record.endswith('==')):
        identifier = 'base64'

    # If we get here, nothing else has matched
    else:
        identifier = 'unknown'

    return identifier
