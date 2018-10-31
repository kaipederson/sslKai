#!/usr/bin/env python

import requests
import time
import sys
import logging

API = 'https://api.ssllabs.com/api/v3/'


def requestAPI(path, payload={}):
    '''This is a helper method that takes the path to the relevant
        API call and the user-defined payload and requests the
        data/server test from Qualys SSL Labs.

        Returns JSON formatted data'''

    url = API + path

    try:
        response = requests.get(url, params=payload)
        print(response.headers)
    except requests.exception.RequestException:
        logging.exception('Request failed.')
        sys.exit(1)

    data = response.json()
    return data


def resultsFromCache(host, publish='off', startNew='off', fromCache='on', all='done'):
    path = 'analyze'
    payload = {
                'host': host,
                'publish': publish,
                'startNew': startNew,
                'fromCache': fromCache,
                'all': all
              }

    data = requestAPI(path, payload)
    try:
        while data['status'] != 'READY' and data['status'] != 'ERROR':
            time.sleep(30)
            data = requestAPI(path, payload)
    except:
        return newScan(host)

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


    while results['status'] != 'READY' and results['status'] != 'ERROR':
        if results['status'] == 'IN_PROGRESS':
            time.sleep(10)
            print("Working on it.\n")
        else:
            time.sleep(5)

        results = requestAPI(path, payload)

    return results
