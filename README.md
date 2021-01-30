# URL_Phish_Analyzer
URL Phishing Tool, Python code to check for malicious markers (work in progress)

Technical notes:
===================
A. Python, non-base libraries required: Selenium & Chromedriver

B. Selenium & chromedriver must be installed for complete results
to be generated, remaining libraries are base Python.
 
C. Code tested on Windows and Linux

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
