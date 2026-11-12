"""Bound the vendor's offline asset command without changing application code."""
import concurrent.futures
import hashlib
import importlib
import json
from pathlib import Path

import django

django.setup()
from django.core.management import call_command

command = importlib.import_module('compressor.management.commands.compress')
original_executor = concurrent.futures.ThreadPoolExecutor


class SerialAssetExecutor(original_executor):
    def __init__(self, max_workers=None, **kwargs):
        # The bundled command hardcodes four workers. Concurrent renders can
        # replace the same CACHE output while another render is opening it.
        super().__init__(max_workers=1, **kwargs)


command.concurrent.futures.ThreadPoolExecutor = SerialAssetExecutor
try:
    call_command('compress', force=True)
finally:
    command.concurrent.futures.ThreadPoolExecutor = original_executor

receipt = {'workers': 1, 'command_sha256': hashlib.sha256(Path(command.__file__).read_bytes()).hexdigest()}
Path('/data/assets-build.json').write_text(json.dumps(receipt, sort_keys=True))
print(json.dumps(receipt), flush=True)
