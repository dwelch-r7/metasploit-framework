"""Perform one real HTTP request inside the isolated target's namespace."""
import base64
import http.client
import json
import sys
import urllib.parse

request = json.loads(sys.argv[1])
body = urllib.parse.urlencode(request['form']) if request['form'] is not None else None
headers = {}
if body is not None:
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
if request['cookies']:
    headers['Cookie'] = '; '.join(key + '=' + value for key, value in request['cookies'].items())
connection = http.client.HTTPConnection('127.0.0.1', 20211, timeout=10)
try:
    connection.request('POST' if body is not None else 'GET', request['path'], body=body, headers=headers)
    response = connection.getresponse()
    print(json.dumps(dict(status=response.status, headers=response.getheaders(), body_base64=base64.b64encode(response.read()).decode())))
finally:
    connection.close()
