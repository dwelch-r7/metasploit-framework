"""Serve a generated test card to the genuine Motion camera consumer."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
import hashlib
import json
import threading
import time

from PIL import Image, ImageDraw


settings = json.loads(Path(__file__).with_name('releases.json').read_text())['camera']
image = Image.new('RGB', (settings['width'], settings['height']), tuple(settings['background']))
ImageDraw.Draw(image).rectangle((settings['width'] // 4, settings['height'] // 4, 3 * settings['width'] // 4, 3 * settings['height'] // 4), fill=tuple(settings['foreground']))
buffer = BytesIO()
image.save(buffer, format='JPEG', quality=92)
frame = buffer.getvalue()
state = {'requests': 0, 'frames': 0, 'sha256': hashlib.sha256(frame).hexdigest()}
guard = threading.Lock()


class Camera(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == '/status.json':
            with guard:
                body = json.dumps(state).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != settings['path']:
            self.send_error(404)
            return
        with guard:
            state['requests'] += 1
        self.send_response(200)
        self.send_header('Content-Type', 'multipart/x-mixed-replace; boundary=module-target-camera')
        self.end_headers()
        deadline = time.monotonic() + 60
        try:
            while time.monotonic() < deadline:
                self.wfile.write(b'--module-target-camera\r\nContent-Type: image/jpeg\r\nContent-Length: '
                                 + str(len(frame)).encode() + b'\r\n\r\n' + frame + b'\r\n')
                self.wfile.flush()
                with guard:
                    state['frames'] += 1
                time.sleep(1 / settings['fps'])
        except (BrokenPipeError, ConnectionResetError):
            pass


server = ThreadingHTTPServer(('127.0.0.1', settings['port']), Camera)
server.daemon_threads = True
server.serve_forever(poll_interval=0.25)
