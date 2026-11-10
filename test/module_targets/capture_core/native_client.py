"""Compose-bound client execution and actual packet evidence; no host networking."""
import base64
import json
import os
from pathlib import Path
import select
import subprocess


class NativeClients:
    def __init__(self):
        self.runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
        self.compose = self.runtime['compose']
        self.artifacts = Path(self.runtime['artifacts'])
        self.commands = []

    def command(self, service, *arguments, stdin=None, timeout=15):
        command = self.compose + ['exec', '-T', service] + list(arguments)
        result = subprocess.run(command, input=stdin, capture_output=True, timeout=timeout)
        receipt = {'service': service, 'argv': list(arguments), 'status': result.returncode, 'stdout_base64': base64.b64encode(result.stdout).decode(), 'stderr_base64': base64.b64encode(result.stderr).decode(), 'stdout': result.stdout.decode('utf-8', 'backslashreplace'), 'stderr': result.stderr.decode('utf-8', 'backslashreplace')}
        self.commands.append(receipt)
        with (self.artifacts / 'native-client-commands.jsonl').open('a') as output:
            output.write(json.dumps(receipt) + '\n')
        return receipt

    def capture(self, label, port, service, *arguments):
        if not label.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Invalid capture label')
        process = subprocess.Popen(self.compose + ['exec', '-T', 'client', 'python3', '/opt/module-target-client.py', 'sniff', '--port', str(port), '--file', '/artifacts/' + label + '.pcap'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ready = b''
        try:
            readable, _, _ = select.select([process.stdout], [], [], 7)
            if not readable:
                raise RuntimeError('Capture controller did not become ready')
            ready = process.stdout.readline()
            if not json.loads(ready).get('ready'):
                raise RuntimeError('Packet capture failed: ' + ready.decode())
            result = self.command(service, *arguments)
        finally:
            output, error = process.communicate(input=b'\n', timeout=22)
            (self.artifacts / (label + '-capture-controller.json')).write_text(json.dumps({'ready': ready.decode(), 'stdout': output.decode(), 'stderr': error.decode(), 'status': process.returncode}, indent=2) + '\n')
        if process.returncode != 0:
            raise RuntimeError('Packet capture controller failed')
        if not (self.artifacts / (label + '.pcap')).is_file():
            raise RuntimeError('Actual packet capture is missing')
        streams = tcp_streams(self.artifacts / (label + '.pcap'))
        if not streams:
            raise RuntimeError('No actual TCP application payload was captured')
        (self.artifacts / (label + '.wire.json')).write_text(json.dumps(streams, indent=2) + '\n')
        return result


def tcp_streams(path):
    """Reassemble the actual Ethernet/IPv4 TCP payloads emitted in a short capture."""
    import socket
    import struct

    data = Path(path).read_bytes()
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>'}.get(data[:4])
    if endian is None or len(data) < 24:
        raise ValueError('Unsupported or empty PCAP header')
    if struct.unpack(endian+'I', data[20:24])[0] != 1:
        raise ValueError('Capture is not Ethernet')
    offset, streams = 24, {}
    while offset < len(data):
        _, _, included, _ = struct.unpack(endian+'IIII', data[offset:offset+16])
        packet = data[offset+16:offset+16+included]
        offset += 16+included
        if len(packet) < 54 or packet[12:14] != b'\x08\x00':
            continue
        ip = packet[14:]
        if ip[9] != 6:
            continue
        ip_length = (ip[0]&15)*4
        total = int.from_bytes(ip[2:4], 'big')
        tcp = ip[ip_length:total]
        source_port, target_port, sequence = struct.unpack('!HHI', tcp[:8])
        payload = tcp[(tcp[12]>>4)*4:]
        if not payload:
            continue
        key = (socket.inet_ntoa(ip[12:16]), source_port, socket.inet_ntoa(ip[16:20]), target_port)
        streams.setdefault(key, []).append((sequence,payload))
    output = []
    for key, fragments in streams.items():
        payload = bytearray()
        position = min(sequence for sequence,_ in fragments)
        for sequence, fragment in sorted(fragments):
            if sequence > position:
                raise ValueError('Gap in captured TCP stream')
            skipped = position-sequence
            payload.extend(fragment[skipped:])
            position = max(position,sequence+len(fragment))
        output.append({'source':key[0], 'source_port':key[1], 'target':key[2], 'target_port':key[3], 'base64':base64.b64encode(payload).decode(), 'hex':payload.hex(), 'text':payload.decode('utf-8','backslashreplace')})
    return output
