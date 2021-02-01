# -*- coding: utf-8 -*-
"""
Created on Sun Jan  3 18:20:46 2021
@author: Eli Lieberman

Technical notes:
===================
A. Python, non-base libraries required: Selenium & Chromedriver
https://www.tecmint.com/install-google-chrome-on-kali-linux/

B. Selenium & chromedriver must be installed for complete results
to be generated, remaining libraries are base Python.
 
C. Code tested on Windows and Linux

D. Test URLs:
"https://sherlockshats.com/"
"https://www.tzometcounseling.com/"


Project Description
=====================
This script tests for several qualitative markers of a fake website 
or phishing scam, using the SUSPECTED URL. A single item may 
not indicate malicious behavior, however the report contains 
several measures, including:
    1. When the site was first registered, fake sites often lack history
    2. Presence of social media meta tags,versus phishers 
       wouldn't include links that allow you to stray from their page
    3. Deceptive URL encoding (punycode), i.e. greek letters like Tau, 
       posing like the letter T but aren't, pointing to 
       malicously registered sites
    4. Presence of contact MAILTO attribute, frequently absent 
       from malicious sites
    5. Review and present site emails, for agreement with 
       hostname, malicious sites will not point visitors 
       back to the authentic site
    6. Return results to user in their browser, as an additional tab
       natively from Python, copy-paste-results.... 
       never leaving python or the browser     

"""
import sys
import requests
from bs4 import BeautifulSoup
import json
import urllib
import re
from selenium import webdriver #not base Python
import time
from urllib.parse import urlparse
import pandas as pd
import webbrowser #for reporting
import tempfile   #for reporting
import numpy as np
np.warnings.filterwarnings('ignore', category=np.VisibleDeprecationWarning) # ignore warning, that does not affect results

'Test if selenium Library installed'
selenium_installed = 'selenium' in sys.modules
if selenium_installed == False:
    print("\n\nSelenium library not present,\nSELENIUM library must be present to generate the complete report,\nReport will be truncated!\n\n ")
    
'User URL capture'
' Two part or three part format.... i.e. https://sherlockshats.com/ OR https://www.tzometcounseling.com/  '
url = input("After a few moments RESULTS are returned to your BROWSER!\nType or paste the COMPLETE suspect URL,\ncommon two or three part format *including HTTP portion*,\nthen hit ENTER:  ")

'RULE, validate URL for Punycode and other malicious misrepresentations'
puny_test = url.isascii()

'Reformat URL for WHOis/rdap lookup'
url_len = len(urlparse(url).netloc.split('.'))
if url_len == 3:
    domain = urlparse(url).netloc.split('.')[1:]
    domain = '.'.join(domain)
elif url_len == 2:
    domain = urllib.request.urlparse(url)[1]
else:
    print("Errors in URL,check for typos")


'Capture & Parse Target Site, create token-header'
headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '3600',
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
    }

#req = requests.get(url, headers)
req = requests.get(url)
soup = BeautifulSoup(req.content, 'html.parser')
req.status_code == 200 # test connectivity to URL
site_status = req.status_code
# print(soup.prettify())
# Print Title, random check of parse results
title = soup.title.get_text() #title dropping tags
#print(title) 

'API Check site registration history on Verisign https://www.openrdap.org/'
# Libraries needed bs4, requests, json, and urllib to parse domain from URL
# Extract domain from URL
from urllib.parse import urlparse
#url_len = len(urlparse(url3).netloc.split('.'))
url_rdap='https://rdap.verisign.com/com/v1/domain/'+domain # domain& tld

# print(url_rdap) #check url string
req_rdap = requests.get(url_rdap)
soup_rdap = BeautifulSoup(req_rdap.content, 'html.parser')
# print(soup_rdap.prettify()) #review BS4 content
rdap_json=json.loads(soup_rdap.text)
'Parse registration data from EVENTS dictionary'
events = rdap_json['events']

'Extract the site Registered Date from the EVENTS dictionary, convert to printable format'
def domain_data():
    for x in rdap_json['events']:
        if 'registration' in x.values():
            for k,v in x.items():
                #print(v,k)
                #print('Site First Registered: ',v)
                #print(v)
                global est
                est = v
    return est
domain_data()
established = est.split("T")[0]

'Use selenium to extract list of emails, not captured with the REQUESTS library'
if selenium_installed == False:
    print("\n\nSelenium library not installed,\nreport will be truncated!\n\n ")
    report = pd.DataFrame(columns=['Site Title','URL Reviewed','Site Status', 'Whois_Date_Registered', 'URL is ASCII'])
    rpt_summary = [title, url,site_status, established,puny_test]
    report.loc[len(report),:] = rpt_summary
    print(report.T.to_string(header=False))
    
    'Display Report as HTML'
    rpt_html = report.T.to_html(header = False, bold_rows = True)
    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html') as f:
        url = 'file://' + f.name
        f.write(rpt_html)
    webbrowser.open(url)
    
else:
    from selenium import webdriver
    import time
    print("\n\nSelenium library is present!\n\n ")
    def render_page(url):
        driver = webdriver.Chrome()
        # driver can be manually pointed to as well
        #driver = webdriver.Chrome(r"C:\Users\elili\AppData\Local\Microsoft\WindowsApps\chromedriver.exe")
        driver.get(url)
        time.sleep(3)
        r = driver.page_source
        #driver.quit()
        return r
    
    'REGEX for all EMAILS'
    r = render_page(url)
    soup_r = BeautifulSoup(r, "html.parser")
    emails = re.findall(r'[\w\.-]+@[\w\.-]+', soup_r.decode('utf-8'))
    
    'RULE, count social media Open Graph tags, "og", checking for two most common meta tags'
    og_t = soup.find_all("meta",  property="og:title")
    og_u = soup.find_all("meta",  property="og:url")
    social_count = len(og_t) + len(og_u)
    
    
    'RULE, determine presence of contact data'
    mailto_check = []
    if "mailto" in soup_r.decode('utf-8'):
        mailto_check = 1 
        
    'RULE, validate agreement of email domains against site domain, list foreign domain emails'
    consistent_emails = []
    suspect_emails = []
    
    for e in emails:
        s = e.split("@")[1]
        if s == domain:
            consistent_emails.append(e)
        else:
            suspect_emails.append(e)
    
    'Aggregate Report Elements'
    total_emails = len(list(set(consistent_emails))) + len(list(set(suspect_emails))) #unique
    consistent_emails_unique = ', '.join(list(set(consistent_emails)))
    suspect_emails_unique = ', '.join(list(set(suspect_emails)))
    report = pd.DataFrame(columns=['Site Title','URL Reviewed','Site Status', 'Whois_Date_Registered', 'URL is ASCII', 'Social Media Contacts','MailTo?','Listed Emails','Consistent_Emails','Suspect Emails'])
    rpt_summary = [title, url,site_status, established,puny_test,social_count,mailto_check, total_emails, consistent_emails_unique, suspect_emails_unique]
    report.loc[len(report),:] = rpt_summary
    #print(report.T.to_string(header=False))
    
    'Display Report, create temporary file and display as HTML'
    #import tempfile
    #import webbrowser
    rpt_html = report.T.to_html(header = False, bold_rows = True)
    
    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html') as f:
        url = 'file://' + f.name
        f.write(rpt_html)
    webbrowser.open(url)

