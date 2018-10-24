import ssllabsscanner
import sys
from time import time
import logging

print("Starting SSL Labs Scan ----------------------------------")

ts = time()

domains = []

with open(str(sys.argv[1]),"r") as file:
    for line in file:
        line = line.strip()
        if line:
            domains.append(line)

for domain in domains:

    print(domain)

    try:
        scan = ssllabsscanner.resultsFromCache(str(domain))
    except:
        scan = ssllabsscanner.newScan(str(domain))

    print(scan)
    ipAddress = scan['endpoints'][0]['ipAddress']
    grade = scan['endpoints'][0]['grade']
    cert = scan['endpoints'][0]['details']['cert']['sigAlg']
    print(domain + " " + ipAddress + " " + grade + " " + cert)


print("\n\nDamn, that took this many seconds", time() - ts)
def SQLWrite(domain, ipAddress, grade, cert):
    return