"""Serve the real text fixtures on target loopback for the HTTP scheme case."""
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import os
import sys


class Handler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        print(json.dumps({'method': self.command, 'path': self.path, 'message': format % args}), flush=True)


os.chdir(sys.argv[1])
HTTPServer(('127.0.0.1', int(sys.argv[2])), Handler).serve_forever()
