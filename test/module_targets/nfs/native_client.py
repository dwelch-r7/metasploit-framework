"""Independent real ONC/RPC: RFC1057 framing and RFC1813 export records."""
import base64
import json
from pathlib import Path
import socket
import struct
import subprocess


class XDRReader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def integer(self):
        assert self.offset + 4 <= len(self.data)
        value = struct.unpack_from('!I', self.data, self.offset)[0]
        self.offset += 4
        return value

    def opaque(self):
        size = self.integer()
        assert size <= 65536 and self.offset + size <= len(self.data)
        value = self.data[self.offset:self.offset + size]
        self.offset += (size + 3) // 4 * 4
        return value

    def string(self):
        return self.opaque().decode()


class NativeNFS:
    def __init__(self, runtime):
        self.runtime, self.commands, self.requests, self.sequence = runtime, [], [], 0

    def process(self, arguments, expected=0):
        process = subprocess.run(arguments, capture_output=True, timeout=30)
        record = dict(argv=arguments, stdout_base64=base64.b64encode(process.stdout).decode(), stderr=process.stderr.decode(errors='replace'), exitstatus=process.returncode)
        self.commands.append(record)
        assert process.returncode == expected, record
        return process.stdout

    def command(self, service, *arguments, expected=0):
        return self.process(self.runtime['compose'] + ['exec', '-T', service] + list(arguments), expected)

    def port(self, service, number, protocol):
        binding = self.process(self.runtime['compose'] + ['port', '--protocol', protocol, service, str(number)]).decode().strip()
        host, port = binding.split(':')
        assert host == '127.0.0.1'
        return int(port)

    @staticmethod
    def exact(stream, size):
        result = b''
        while len(result) < size:
            part = stream.recv(size - len(result))
            assert part, 'RPC peer closed before its complete record'
            result += part
        return result

    def call(self, service, protocol, port, program, version, procedure, arguments=b''):
        self.sequence += 1
        xid = 0x4e465300 + self.sequence
        message = struct.pack('!10I', xid, 0, 2, program, version, procedure, 0, 0, 0, 0) + arguments
        endpoint = ('127.0.0.1', self.port(service, port, protocol))
        wire = struct.pack('!I', len(message) | 0x80000000) + message if protocol == 'tcp' else message
        record = dict(service=service, protocol=protocol, port=port, endpoint=endpoint, program=program, version=version, procedure=procedure, request_base64=base64.b64encode(message).decode(), wire_request_base64=base64.b64encode(wire).decode())
        self.requests.append(record)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM) as stream:
            stream.settimeout(3)
            if protocol == 'tcp':
                stream.connect(endpoint)
                stream.sendall(wire)
                response = b''
                while True:
                    marker = struct.unpack('!I', self.exact(stream, 4))[0]
                    size = marker & 0x7fffffff
                    assert size <= 65536
                    response += self.exact(stream, size)
                    if marker & 0x80000000:
                        break
            else:
                stream.sendto(wire, endpoint)
                response, _ = stream.recvfrom(65536)
        record['response_base64'] = base64.b64encode(response).decode()
        reader = XDRReader(response)
        assert [reader.integer(), reader.integer(), reader.integer()] == [xid, 1, 0]
        reader.integer()
        reader.opaque()
        record['accept_status'] = reader.integer()
        assert record['accept_status'] == 0, record
        return reader

    def maps(self, service, protocol):
        reader = self.call(service, protocol, 111, 100000, 2, 4)
        rows = []
        while reader.integer():
            rows.append([reader.integer() for _ in range(4)])
        assert reader.offset == len(reader.data)
        return rows

    def exports(self, service, protocol):
        reader = self.call(service, protocol, 111, 100000, 2, 3, struct.pack('!4I', 100005, 1, 6 if protocol == 'tcp' else 17, 0))
        port = reader.integer()
        assert port == 2049 and reader.offset == len(reader.data)
        reader = self.call(service, protocol, port, 100005, 1, 5)
        exports = []
        while reader.integer():
            path, groups = reader.string(), []
            while reader.integer():
                groups.append(reader.string())
            exports.append([path, groups])
        assert reader.offset == len(reader.data)
        return exports

    def filesystem(self):
        code = 'import hashlib,json,pathlib; root=pathlib.Path("/exports"); print(json.dumps({str(p):dict(mode=p.stat().st_mode,uid=p.stat().st_uid,gid=p.stat().st_gid,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(root.rglob("*")) if p.is_file()},sort_keys=True))'
        return json.loads(self.command('open', 'python3', '-c', code))

    def write(self, path, **extra):
        Path(path).write_text(json.dumps(dict(commands=self.commands, requests=self.requests, **extra), indent=2) + '\n')
