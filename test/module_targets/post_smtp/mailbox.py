"""Read genuine Exim mailbox messages; do not synthesize application mail."""
import base64
import email.policy
import json
import mailbox
from pathlib import Path
import sys
import time

minimum = int(sys.argv[1])
path = Path('/var/spool/exim4/module-target-mail/module_target')
deadline = time.monotonic() + 15
while True:
    messages = []
    if path.is_file():
        box = mailbox.mbox(path, create=False)
        try:
            for raw in box:
                message = email.message_from_bytes(raw.as_bytes(), policy=email.policy.default)
                part = message.get_body(preferencelist=('plain',))
                messages.append({
                    'to': str(message['To']), 'subject': str(message['Subject']),
                    'body': part.get_content() if part else None,
                    'raw_base64': base64.b64encode(raw.as_bytes()).decode('ascii')
                })
        finally:
            box.close()
    if len(messages) >= minimum:
        print(json.dumps(messages))
        break
    if time.monotonic() >= deadline:
        raise RuntimeError('Genuine SMTP mailbox delivery deadline exceeded')
    time.sleep(0.1)
