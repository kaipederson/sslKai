import threading
from queue import Queue
import ssllabsscanner
import sys
import time
import requests

print_lock = threading.Lock()

num_threads = 0;

'''
scan_domain uses the ssllabsscanner functions resultsFromCache (if possible) or newScan. The returned JSON object
contains information regarding the SSLLab Scan. We're just concerned with the domain, IP, grade, and certificate.
'''
def scan_domain(domain):

    with print_lock:
        print("\nStarting thread {}".format(threading.current_thread().name))
        print("Scanning this domain " + domain + "\n")

    #try:
    #   scan = ssllabsscanner.resultsFromCache(str(domain))
    #except:
    time.sleep(1)
    scan = ssllabsscanner.newScan(str(domain))



    with print_lock:
        print("{}".format(threading.current_thread().name))
        print(scan)

        try:
            ipAddress = scan['endpoints'][0]['ipAddress']

        except Exception:
            ipAddress = "ERR"

        try:
            grade = scan['endpoints'][0]['grade']

        except Exception:
            grade = "ERR"

        try:
            cert = scan['endpoints'][0]['details']['cert']['sigAlg']

        except  Exception:
            cert = "ERR"

        print(domain + " " + ipAddress + " " + grade + " " + cert)
        print("Completed after = {0:.5f}".format(time.time() - start))



'''

Main Application

'''


print("Starting SSL Labs Scan ----------------------------------")

scan_info = requests.get("https://api.ssllabs.com/api/v3/info")
num_threads = (scan_info.json())['maxAssessments']

print(scan_info.json())

print("SSLLabs currently allows " + str(num_threads) + " concurrent assessments.\n")


'''
Helper method to write to Unmesha's SQL database. Should go inside of a lock in the scan_domain method.
'''
def SQLWrite(domain, ipAddress, grade, cert):
    return


def process_queue():
    while True:
        domain = domain_queue.get()
        scan_domain(domain)
        time.sleep(1)
        domain_queue.task_done()

domain_queue = Queue()

domain_list = []

with open(str(sys.argv[1]),"r") as file:
    for line in file:
        line = line.strip()
        if line:
            domain_list.append(line)


for i in range(num_threads):
    t = threading.Thread(target=process_queue)
    t.daemon = True
    t.start()
    num_threads = (requests.get("https://api.ssllabs.com/api/v3/info").json())['maxAssessments']
    print("Updated max_threads: " + str(num_threads))

start = time.time()

for domain in domain_list:
    domain_queue.put(domain)
    time.sleep(1)

domain_queue.join()


print("Execution time = {0:.5f}".format(time.time() - start))