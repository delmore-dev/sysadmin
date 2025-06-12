#This script will search Microsoft's monthly updates for any KBs for the following:
#Windows 10 22H2 (x64), Server 2012, Server 2016, Server 2019, and Office 2016 (both x32 and x64)

import requests
import json
from datetime import datetime


#formatting date and pulling from api
currentdate = datetime.now()
date = currentdate.strftime("%Y-%b")
url = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{date}"
headers = {"Accept" : "application/json"}
r = requests.get(url, headers=headers)
response_dict = r.json()
vuln_dict = response_dict['Vulnerability']

#product IDs
pid_s2016 = '10816'
pid_s2019 = '11571'
pid_w10 = '12097'
pid_Office16x32 = '10753'
pid_Office16x64 = '10754'
pid_s2012 = '10483'

#sets for URLS
set_2016 = set()
set_2019 = set()
set_w10 = set()
set_Office16x32 = set()
set_Office16x64 = set()
set_s2012 = set()

#drilling down to product IDs, and pulling the URLs associate with the KB.
for vuln in vuln_dict:
    remediations = vuln['Remediations'] 
    for remediation in remediations:
        pids = remediation['ProductID']
        for pid in pids:
            if pid == pid_s2016:
                set_2016.add(remediation['URL'])
            elif pid == pid_s2019:
                set_2019.add(remediation['URL'])
            elif pid == pid_w10:
                set_w10.add(remediation['URL'])
            elif pid == pid_Office16x32:
                set_Office16x32.add(remediation['URL'])
            elif pid == pid_Office16x64:
                set_Office16x64.add(remediation['URL'])
            elif pid == pid_s2012:
                set_s2012.add(remediation['URL'])
            else:
                pass

#turning sets into lists
list_2016 = list(set_2016)
list_2019 = list(set_2019)
list_w10 = list(set_w10)
list_office32 = list(set_Office16x32)
list_office64 = list(set_Office16x64)
list_2012 = list(set_s2012)

#printing the lists
print (f"Server 2016 remediations KBs: {list_2016}\n")
print (f"Server 2019 remediations KBs: {list_2019}\n")
print (f"Windows 10 remediations KBs: {list_w10}\n")
print (f"Office 2016 x32 KBs: {list_office32}\n")
print (f"Office 2016 x64 KBs: {list_office64}\n")
print (f"Server 2012 remediations KBs: {list_2012}\n")