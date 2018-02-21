# Author: Adam Portier <aporti01@villanova.edu>
# Date: October 23, 2017
# dns-audit.py: Library functions to support DNS TXT record research

import re
import sys
import time

from dns.resolver import *

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


# Given a DNS TXT record, performs a series of pattern matches and attempts to classify it
def classifyTxtRecord(record):

    # The " " around the record were messing with the regex matches
    record = record.replace('"', '')

    identifier = ""

    ##### Formal TXT Record Formats #####

    # SPF Records
    if (record.lower().startswith('v=spf1')):
        identifier = 'spf'

    # Malformed or multi-line SPF records
    elif (record.lower().startswith('include:') or
            record.lower().startswith('v=spf3') or
            record.lower().startswith('ip4:')):
        identifier = 'spf-misconfigured'

    # SenderID records
    elif (record.lower().startswith('spf2.0/')):
        identifier = 'sender-id'

    # Malformed or multi-line SenderID records
    elif (record.lower().startswith('v=spf2.0')):
        identifier = 'sender-id-misconfigured'

    # DKIM records
    elif (record.lower().startswith('v=dkim1')):
        identifier = 'dkim'

    # Malformed or multi-line DKIM records
    elif (record.lower().startswith('k=rsa')):
        identifier = 'dkim-misconfigured'

    # DMARC records
    elif (record.lower().startswith('v=dmarc1')):
        identifier = 'dmarc'

    ##### END Formal TXT Record Formats #####

    ##### Informal TXT Record Formats #####

    #### Domain Verification ####
    
    ### Email SaaS Verification ###

    # G Suite domain verfication
    # https://support.google.com/a/answer/183895?hl=en
    elif (record.lower().startswith('google-site-verification')):
        identifier = 'google-site-verification'

    # Office 365 domain ownership verification
    # https://support.office.microsoft.com/en-us/article/Gather-the-information-you-need-to-create-Office-365-DNS-records-77f90d4a-dc7f-4f09-8972-c1b03ea85a67
    elif (record.lower().startswith('ms=')):
        identifier = 'office365ms'

    # Outlook.com domain ownership verification
    # http://www.omegaweb.com/how-to-configure-a-custom-domain-with-outlook-com/
    # https://support.office.com/en-us/article/Use-your-own-domain-in-Outlook-com-Premium-61e21366-c809-44e5-a414-9bab47110e5f?ui=en-US&rs=en-US&ad=US
    elif (record.lower().startswith('v=msv1')):
        identifier = 'outlookmsv1'

    # Another Office 365 domain ownership verification format
    # http://www.colome.org/office-365-dns-configuration/
    elif (record.lower().startswith('v=verifydomain')):
        identifier = 'office365verifydomain'

    # Amazon Simple Email Service (SES)
    # http://docs.aws.amazon.com/ses/latest/DeveloperGuide/dns-txt-records.html
    elif (record.lower().startswith('amazonses')):
        identifier = 'amazonses'

    # Domain uses the Salesforce Pardot email marketing platform
    # http://help.pardot.com/customer/portal/articles/2128543-setting-up-tracker-subdomain-cname-
    elif (record.lower().startswith('pardot')):
        identifier = 'salesforce-pardot'

    # Domain uses postmaster.mail.ru service for collecting mail statistics
    # https://serverfault.com/questions/767718/what-is-dns-txt-record-mailru-verification
    elif (record.lower().startswith('mailru-verification')):
        identifier = 'mailru-verification'

    # Domain uses the Yandex platform for managing email
    # https://yandex.com/support/webmaster/service/rights.html
    elif (record.lower().startswith('yandex-verification')):
        identifier = 'yandex-verification'

    # Verification for hosted Mail.ru email
    # https://help.mail.ru/biz/domain/verification_settings/other/confirm
    elif (record.lower().startswith('mailru-domain:')):
        identifier = 'mailru-domain'

    # Tied to some mail.ru email service, could not find more information in English
    # https://www.youtube.com/watch?v=GHy8aH08QNo
    elif (record.lower().startswith('wmail-verification:')):
        identifier = 'wmail-verification'

    # Hosted email through Zoho
    # https://www.zoho.com/mail/help/adminconsole/domain-verification.html
    elif (record.lower().startswith('zoho-verification=')):
        identifier = 'zoho-verification'

    # SendInBlue email marketing service
    # https://help.sendinblue.com/hc/en-us/articles/208836149-Step-3-Creating-a-new-sender
    elif (record.lower().startswith('sendinblue-code:')):
        identifier = 'sendinblue-code'

    ### END Email SaaS Verification ###

    ### SaaS Service Verification ###

    # Facebook provided collaboration service similar to Slack
    # https://fb.facebook.com/help/work/431877453687567/
    elif (record.lower().startswith('workplace-domain-verification=')):
        identifier = 'workplace-domain-verification'

    # Have I Been Pwned only allows searches against compromised email lists if you own the
    # domain in question
    # https://haveibeenpwned.com/DomainSearch
    elif (record.lower().startswith('have-i-been-pwned-verification=')):
        identifier = 'have-i-been-pwned-verification'

    # Domain uses GoToMeeting with Single Sign-on through AD
    # https://support.citrixonline.com/en_US/Webinar/all_files/G2W710101
    elif (record.lower().startswith('citrix-verification-code=')):
        identifier = 'citrix-verification-code'

    # Domain uses the StatusPage outage communication / tracking tool
    # https://help.statuspage.io/knowledge_base/topics/domain-ownership
    elif (record.lower().startswith('status-page-domain-verification=')):
        identifier = 'status-page-domain-verification'

    # Domain uses Bugcrowd for identity verification and has enabled SAML based SSO
    # for their account
    # https://docs.bugcrowd.com/v1.0/docs/single-sign-on
    elif (record.lower().startswith('bugcrowd-verification=')):
        identifier = 'bugcrowd-verification'

    # Domain owner has included domain in Keybase's identify proof using
    # the "keybase prove dns" option
    # https://keybase.io/docs/command_line
    elif (record.lower().startswith('keybase-site-verification=')):
        identifier = 'keybase-site-verification'

    # Domain uses Wrike for project management
    # Could not find a specific reference to what this record is used to verify
    elif (record.lower().startswith('wrike-verification=')):
        identifier = 'wrike-verification'

    # Domain uses Sage Intacct to manage financial data
    # Could not find specific example of what this record is used to verify
    elif (record.lower().startswith('intacct-esk=')):
        identifier = 'intacct-esk'

    # Domain uses a Facebook verified page for their business
    # https://developers.facebook.com/docs/sharing/domain-verification
    elif (record.lower().startswith('facebook-domain-verification=')):
        identifier = 'facebook-domain-verification'

    ### END SaaS Service Verification ###

    ### Advertising Services ###

    # Brave Browser account verification; used to sign a domain up to recieve bitcoin payments
    # from Brave in exchange for the Brave browser blocking their advertisements 
    # https://github.com/brave-intl/publishers/blob/master/app/services/publisher_dns_record_generator.rb
    # https://brave.com/faq/#brave-payments
    elif (record.lower().startswith('brave-ledger-verification')):
        identifier = 'brave-ledger-verification'

    ### END Advertising Services ###

    ### Developer Tools / Infrastructure ###

    # Loader.io service for automated testing of API Endpoints
    # http://support.loader.io/article/20-verifying-an-app
    elif (record.lower().startswith('loaderio=')):
        identifier = 'loaderio'

    # Domain uses the DocuSign electronic signature service
    # https://www.docusign.com/supportdocs/ndse-admin-guide/Content/domains.htm
    elif (record.lower().startswith('docusign=')):
        identifier = 'docusign'

    # Domain uses the Adobe Sign service to electronically sign documents
    # https://helpx.adobe.com/sign/help/domain_claiming.html
    elif (record.lower().startswith('adobe-sign-verification=')):
        identifier = 'adobe-sign-verification'

    # Application is hosted using Firebase
    # https://firebase.google.com/docs/hosting/custom-domain
    elif (record.lower().startswith('firebase=')):
        identifier = 'firebase'

    # Blitz load testing SaaS
    # https://www.blitz.io/
    elif (record.lower().startswith('blitz=')):
        identifier = 'blitz'

    # Domain uses Detectify to scan for vulnerabilties
    # https://support.detectify.com/customer/en/portal/articles/2836806-verification-with-dns-txt-
    elif (record.lower().startswith('detectify-verification=')):
        identifier = 'detectify-verification'

    # Domain uses Tinfoil Security services to scan domain for vulnerabilities
    # https://www.tinfoilsecurity.com/privacy
    elif (record.lower().startswith('tinfoil-site-verification:')):
        identifier = 'tinfoil-site-verification'

    # Domain uses the Adobe provided SAML2 Identity Provider service
    # https://helpx.adobe.com/enterprise/help/verify-domain-ownership.html
    elif (record.lower().startswith('adobe-idp-site-verification')):
        identifier = 'adobe-idp-site-verification'

    # Domain verification for Sophos Email gateway service
    # https://community.sophos.com/kb/en-us/124401
    # https://community.sophos.com/kb/en-us/124703
    elif (record.lower().startswith('sophos-domain-verification=')):
        identifier = 'sophos-domain-verification'

    # Domain verification for Dropbox Business
    # https://www.dropbox.com/help/business/domain-verification-invite-enforcement
    elif (record.lower().startswith('dropbox-domain-verification=')):
        identifier = 'dropbox-domain-verification'

    # Domain uses Atlassian Cloud services (Confluence Wiki)
    # https://confluence.atlassian.com/cloud/domain-verification-873871234.html
    elif (record.lower().startswith('atlassian-domain-verification=')):
        identifier = 'atlassian-domain-verification'

    # Domain uses Cisco Webex conferencing
    # https://help.webex.com/docs/DOC-4860
    elif ((record.lower().startswith('cisco-ci-domain-verification=')) or
            (record.lower().startswith('ciscocidomainverification='))):
        identifier = 'cisco-ci-domain-verification'

    # Domain uses LogMeIn with ADFS for Single Sign-on
    # https://secure.logmein.com/welcome/webhelp/EN/CentralUserGuide/LogMeIn/Using_ADFS_LogMeIn_Central.html
    elif (record.lower().startswith('logmein-domain-confirmation')):
        identifier = 'logmein-domain-confirmation'
    
    # Domain uses the CloudBees Jenkins build service with SSO enabled
    # https://docs.secureauth.com/display/CAD/Cloudbees
    elif (record.lower().startswith('cloudbees-domain-verification:')):
        identifier = 'cloudbees-domain-verification'

    # Domain uses Moxtra for collaboration with SSO enabled
    # https://support.bitium.com/administration/saml-moxtra/
    elif (record.lower().startswith('moxtra-site-verification=')):
        identifier = 'moxtra-site-verification'

    # Domain hosts videos on Dailymotion and has verified ownership so it can monitize them
    # https://faq.dailymotion.com/hc/en-us/articles/211458338-Verification-Methods
    elif (record.lower().startswith('dailymotion-domain-verification=')):
        identifier = 'dailymotion-domain-verification'

    # Domain uses Botify to crawl their websites (SEO)
    # https://www.botify.com/support/site-validation/
    elif (record.lower().startswith('botify-site-verification=')):
        identifier = 'botify-site-verification'

    # Domain has a custom API documentation domain in Postman
    # https://www.getpostman.com/docs/postman/api_documentation/adding_and_verifying_custom_domains
    elif (record.lower().startswith('postman-domain-verification=')):
        identifier = 'postman-domain-verification'

    # Perhaps related to Intermedia AppID (SSO), can't find any definite information
    # https://www.intermedia.net/products/appid
    elif (record.lower().startswith('appid=')):
        identifier = 'appid'

    # Domain uses Favro for workflow management and OneLogin SSO
    # https://help.favro.com/configure-favro/enterprise/single-sign-on-setup-with-onelogin
    elif (record.lower().startswith('favro-verification=')):
        identifier = 'favro-verification'

    # Domain is integrated with the LINE Works platform
    # https://developers.worksmobile.com/jp/document/3012006
    elif (record.lower().startswith('worksmobile-certification=')):
        identifier = 'worksmobile-certification'

    # Proof of domain ownership to use Cloudpiercer security scanning tool
    # https://cloudpiercer.org/
    elif (record.lower().startswith('cloudpiercer-verification=')):
        identifier = 'cloudpiercer-verification'

    # Perhaps related to Spycloud security system
    # https://spycloud.com
    elif (record.lower().startswith('spycloud-domain-verification=')):
        identifier = 'spycloud-domain-verification'

    # Domain uses (or has used) the Cisco Threat Awareness scanner tool
    # https://supportforums.cisco.com/t5/security-documents/cisco-threat-awareness-service-frequently-asked-questions/ta-p/3159415
    elif (record.lower().startswith('cisco-site-verification=')):
        identifier = 'cisco-site-verification'

    # Most likely used in verification of domain ownership for Thousandeyes monitoring solution
    elif (record.lower().startswith('thousandeyes:')):
        identifier = 'thousandeyes'

    # Domain uses the OpenVoice audio conferencing product from LogMeIn
    elif (record.lower().startswith('logmein-verification-code=')):
        identifier='logmein-openvoice'

    # Registers domain to work with the cloudControl platform for hosting
    # https://github.com/castle/cloudcontrol-documentation/blob/master/Add-on%20Documentation/Deployment/Alias.md
    elif (record.lower().startswith('cloudcontrol-verification:')):
        identifier = 'cloudcontrol'

    ### END Developer Tools / Infrastructure ###

    ### SSL Certificates ###

    # GoDaddy SSL Certificate Domain Verification
    # https://www.godaddy.com/community/SSL-And-Security/SSL-Domain-Verification-with-DNS/m-p/42641#M378
    elif (record.lower().startswith('dzc=')):
        identifier = 'dzc'

    # Domain verification for GlobalSign SSL Certificates service
    # https://support.globalsign.com/customer/portal/articles/2167245-performing-domain-verification---dns-txt-record
    elif (record.lower().startswith('globalsign-domain-verification') or
            record.lower().startswith('_globalsign-domain-verification=')):
        identifier = 'globalsign-domain-verification'

    ### END SSL Certificates ###

    #### END Domain Verification ####

    #### Service Location ####

    # Location of Fuse ESB message routing service
    # https://developers.redhat.com/products/fuse/overview/?referrer=jbd
    elif (record.lower().startswith('fuseserver=')):
        identifier = 'fuseserver'

    # Domain uses Symantec Mobile Management to identify / protect mobile devices on
    # their network. This is the iOS agent string to find the enrollment server.
    # https://support.symantec.com/en_US/article.HOWTO77270.html
    elif ((record.lower().startswith('osiagentregurl=')) or
            (record.lower().startswith('android-mdm-enroll='))):
        identifier = 'symantec-mdm'

    # Domain is using Ivanti Landesk for managing mobile devices
    # https://help.ivanti.com/ld/help/en_US/LDMS/10.0/Mobility/mobl-DNS.htm
    elif ((record.lower().startswith('ios-enroll=')) or
            (record.lower().startswith('android-enroll='))):
        identifier = 'ivanti-landesk'

    # Bittorrent Tracker Preferences
    # http://www.bittorrent.org/beps/bep_0034.html
    elif (record.lower().startswith('bittorrent')):
        identifier = 'bittorrent'

    #### END Service Location ####

    ##### More General / Tail Matches #####

    # Catch-all identifier for patterns with no documented use case, probably fragments of
    # another documented use case
    elif ((record.lower().startswith('as=')) or
           (record.lower().startswith('i=')) or
           (record.lower().startswith('www=')) or
           (record.lower().startswith('v=')) or
           (record.lower().startswith('t=')) or
           (record.lower().startswith("p=")) or
           (record.lower().startswith('bio=')) # https://twitter.com/peterkarsai/status/520200572428095488
           ):
        identifier = 'no-documented-case'

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
    elif ((record.endswith('==')) or (record.endswith('='))):
        identifier = 'base64'

    # If we get here, nothing else has matched
    else:
        identifier = 'unknown'

    return identifier
