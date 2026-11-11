import json
from pathlib import Path
import urllib.request

assert Path('/runtime/ready').is_file()
with urllib.request.urlopen('http://127.0.0.1:11434/api/version', timeout=3) as response:
    assert json.load(response)['version'] == '0.1.48'
