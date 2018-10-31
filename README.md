# ssllabs.py
Python module for the Qualys SSL Labs Server Test

Dependencies:

Requires the third-party Python Requests library - http://docs.python-requests.org/en/latest/

Developed using Python 2.7.10

Use:

Download module and navigate inside ssllabs folder.

Then:

import ssllabsscanner

For results from cache:

data = ssllabsscanner.resultsFromCache("www.qaulys.com")

data now contains a JSON object that can be parsed for your needs.

For retrieving the data from a new scan:

data = ssllabsscanner.newScan("www.qualys.com")

data now contains a JSON object that can be parsed for your needs.
