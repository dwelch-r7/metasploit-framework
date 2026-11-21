"""Stock Perl/procfs observations and independent real API session delivery."""

from pathlib import Path
import base64
import copy
import csv
import datetime
import http.client
import io
import json
import os
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'dizquetv'))
from native_probe import Native


class SessionNative(Native):
    def process_state(self, port):
        assert 0 < port < 65536
        raw = self.command('procfs', 'perl', '/opt/module-target-dizquetv-observe.pl', 'state').decode()
        processes, connections = [], []
        for row in csv.reader(io.StringIO(raw), delimiter='\t'):
            if row[0] == 'process':
                _, pid, stat, command, status, inodes = row
                stat, command, status = (bytes.fromhex(value).decode(errors='replace') for value in [stat, command, status])
                fields = stat[stat.rindex(')') + 1:].split()
                assert len(fields) >= 20
                uid = re.search(r'^Uid:\s+(\d+)', status, re.MULTILINE)
                assert uid
                processes.append(dict(pid=int(pid), ppid=int(fields[1]), state=fields[0], birth=fields[19], uid=uid[1],
                                      command=command.replace('\0', ' ').strip(), connection_inodes=inodes.split(',') if inodes else []))
            else:
                assert row[0] == 'network' and row[1] in ['tcp', 'tcp6']
                for line in bytes.fromhex(row[2]).decode().splitlines()[1:]:
                    fields = line.split()
                    if int(fields[2].rsplit(':', 1)[1], 16) == port and fields[3] != '06':
                        connections.append(dict(local=fields[1], remote=fields[2], state=fields[3], inode=fields[9]))
        return dict(processes=processes, connections=connections)

    def baseline(self):
        return json.loads((Path(self.runtime['artifacts']) / 'dizquetv-state.json').read_text())['baseline']

    def restore(self):
        baseline = self.baseline()
        if self.snapshot() != baseline:
            assert self.set_settings(baseline['settings'])['status'] == 200
        assert self.snapshot() == baseline
        return dict(restored=True)

    def arm(self, command):
        baseline = self.baseline()
        assert self.snapshot() == baseline
        candidate = copy.deepcopy(baseline['settings'])
        candidate['ffmpegPath'] = '" >/dev/null 2>&1; ' + command + '; : #'
        response = self.set_settings(candidate)
        assert response['status'] == 200, response
        assert self.settings() == candidate
        return dict(armed=True, command_base64=base64.b64encode(command.encode()).decode(), settings=candidate)

    def trigger(self):
        # The real exec callback remains pending for a foreground shell. Keep
        # that HTTP connection bounded but alive until graceful session exit.
        endpoint = self.runtime['endpoints']['target']
        client = http.client.HTTPConnection(endpoint['host'], endpoint['port'], timeout=90)
        try:
            client.request('GET', '/api/version')
            response = client.getresponse()
            raw = response.read()
            result = dict(status=response.status, body_base64=base64.b64encode(raw).decode(), json=json.loads(raw))
            self.journal['http'].append(dict(method='GET', path='/api/version', response=result))
            assert response.status == 200 and result['json']['dizquetv'] == '1.5.3', result
            return result
        finally:
            client.close()


def main():
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    action, *arguments = sys.argv[1:]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f').lower()
    native = SessionNative(runtime, Path(runtime['artifacts']) / ('dizquetv-session-native-' + action + '-' + stamp))
    try:
        if action == 'state':
            result = native.process_state(int(arguments[0]))
        elif action in ['file', 'remove']:
            result = native.file(arguments[0], remove=action == 'remove')
        elif action == 'arm':
            result = native.arm(base64.b64decode(arguments[0], validate=True).decode())
        elif action == 'restore':
            result = native.restore()
        elif action == 'trigger':
            result = native.trigger()
        else:
            raise ValueError('Unsupported session-native action')
        native.journal['result'] = result
        print(json.dumps(result))
    except Exception as error:
        native.journal['error'] = dict(type=type(error).__name__, message=str(error))
        raise
    finally:
        native.save()


if __name__ == '__main__':
    main()
