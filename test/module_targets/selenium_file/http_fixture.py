"""Serve the real text fixtures on target loopback for the HTTP scheme case."""
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import os
import sys


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/redirect-empty.txt':
            self.send_response(302)
            self.send_header('Location', '/empty.txt')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        super().do_GET()

    def log_message(self, format, *args):
        print(json.dumps({'method': self.command, 'path': self.path, 'message': format % args}), flush=True)


os.chdir(sys.argv[1])
HTTPServer(('127.0.0.1', int(sys.argv[2])), Handler).serve_forever()
