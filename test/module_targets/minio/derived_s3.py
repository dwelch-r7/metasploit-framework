"""Independently authenticate with credentials parsed from actual owner loot."""
import hashlib
import json
from pathlib import Path
import sys

from native import Native


def main(runtime_path, loot_path, evidence_path):
    runtime = json.loads(Path(runtime_path).read_text())
    raw = Path(loot_path).read_bytes()
    environment = json.loads(raw)['MinioEnv']
    directory = Path(evidence_path)
    directory.mkdir()
    runtime['artifacts'] = str(directory)
    client = Native(runtime)
    client.settings = dict(client.settings, root_user=environment['MINIO_ROOT_USER'],
                           root_password=environment['MINIO_ROOT_PASSWORD'])
    baseline = None
    try:
        client.initialize_client()
        baseline = client.snapshot()
        client.bucket_attempted = True
        client.mc('mb', 'lab/' + client.bucket)
        proof = ('actual module-derived S3 ' + client.nonce).encode()
        client.command('node1', 'sh', '-c', 'umask 077; cat > "$1"', 'sh', client.proof, stdin=proof)
        target = 'lab/' + client.bucket + '/proof-0.txt'
        client.mc('cp', client.proof, target)
        stat, _ = client.mc('stat', target)
        assert any(row.get('size') == len(proof) for row in client.documents(stat))
        read, _ = client.mc('cat', target, json_mode=False)
        assert read == proof
        client.mc('rm', target)
    finally:
        errors = client.cleanup(baseline)
        result = dict(loot_path=str(Path(loot_path).resolve()), loot_sha256=hashlib.sha256(raw).hexdigest(),
                      credential_source='actual owner JSON loot, no fixture credential fallback',
                      commands=client.commands, facts=client.facts, cleanup_errors=errors)
        (directory / 'derived-s3.json').write_text(json.dumps(result, indent=2) + '\n')
        assert not errors and client.facts.get('restored') is True, result
    print(json.dumps(dict(status='module_derived_s3_passed', restored=True)))


if __name__ == '__main__':
    main(*sys.argv[1:])
