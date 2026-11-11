"""Fetch the unmodified vendor-distributed SmolLM GGUF with an exact digest."""
import hashlib
from pathlib import Path
import urllib.request

DIGEST = 'eb2c714d40d4b35ba4b8ee98475a06d51d8080a17d2d2a75a23665985c739b94'
URL = 'https://registry.ollama.ai/v2/library/smollm/blobs/sha256:' + DIGEST
path = Path('/lab/smollm-135m.gguf')
hash_value = hashlib.sha256()
with urllib.request.urlopen(URL, timeout=60) as source, path.open('wb') as output:
    while chunk := source.read(1024 * 1024):
        hash_value.update(chunk)
        output.write(chunk)
assert path.stat().st_size == 91727296
assert hash_value.hexdigest() == DIGEST
print('Verified genuine SmolLM GGUF:', DIGEST, flush=True)
