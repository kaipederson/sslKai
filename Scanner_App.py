import threading
from queue import Queue
import sys
import time
import requests
import logging

print_lock = threading.Lock()

num_threads = 0;
threads_running = 0;
max_assessments = (requests.get("https://api.ssllabs.com/api/v3/info").json())['maxAssessments'];
curr_assessments = (requests.get("https://api.ssllabs.com/api/v3/info").json())['currentAssessments'];

API = 'https://api.ssllabs.com/api/v3/'


def requestAPI(path, payload={}):
    '''This is a helper method that takes the path to the relevant
        API call and the user-defined payload and requests the
        data/server test from Qualys SSL Labs.

        Returns JSON formatted data'''

    url = API + path

    try:
        response = requests.get(url, params=payload)
        #print(response.headers)

    except requests.exception.RequestException:
        logging.exception('Request failed.')
        sys.exit(1)

    while(response.status_code == 429):
        print("call me icarus")
        time.sleep(10)
        response = requests.get(url, params=payload)

    data = response.json()
    return data

def newScan(host, publish='off', startNew='on', all='done', ignoreMismatch='on'):
    path = 'analyze'
    payload = {
                'host': host,
                'publish': publish,
                'startNew': startNew,
                'all': all,
                'ignoreMismatch': ignoreMismatch
              }
    results = requestAPI(path, payload)

    payload.pop('startNew')

    try:
        while results['status'] != 'READY' and results['status'] != 'ERROR':
            if results['status'] == 'IN_PROGRESS':
                time.sleep(10)
            else:
                time.sleep(5)

            results = requestAPI(path, payload)
    except:
        print("An error occurred")

    return results


'''
scan_domain uses the ssllabsscanner functions resultsFromCache (if possible) or newScan. The returned JSON object
contains information regarding the SSLLab Scan. We're just concerned with the domain, IP, grade, and certificate.
'''

def scan_domain(domain):

    with print_lock:
        print("\nStarting thread {}".format(threading.current_thread().name))
        print("Scanning " + domain)

    time.sleep(1)
    scan = newScan(str(domain))

    with print_lock:
        print("{}".format(threading.current_thread().name))
        #print(scan)

        try:
            ipAddress = scan['endpoints'][0]['ipAddress']

        except Exception:
            ipAddress = "ERR"

        try:
            grade = scan['endpoints'][0]['grade']

        except Exception:
            grade = "ERR"

        try:
            cert = scan['certs'][0]['sigAlg']

        except  Exception:
            cert = "ERR"

        SQLWrite(domain, ipAddress, grade, cert)

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


for i in range(num_threads - 1):
    while(max_assessments <= curr_assessments):
        print("Max " + str(max_assessments) + " curr " + str(curr_assessments))
        time.sleep(1)
        max_assessments = (requests.get("https://api.ssllabs.com/api/v3/info").json())['maxAssessments']
        curr_assessments = (requests.get("https://api.ssllabs.com/api/v3/info").json())['currentAssessments']

    t = threading.Thread(target=process_queue)
    print("created thread " + str(i))
    t.daemon = True
    t.start()
    num_threads = (requests.get("https://api.ssllabs.com/api/v3/info").json())['maxAssessments']

start = time.time()

for domain in domain_list:
    domain_queue.put(domain)
    time.sleep(1)

domain_queue.join()


print("Execution time = {0:.5f}".format(time.time() - start))