"""Capture actual broker handshakes using the published OTP wire format.

This is an independent native control, not a replacement target. Reads retain
actual receive chunk sizes; no artificial fragmentation or coalescing is used.
"""
import hashlib
import json
import socket
import struct
import sys

request = json.load(sys.stdin)
records = []
sock = socket.create_connection((request["host"], 25672), timeout=5)
sock.settimeout(5)


def send_frame(body):
    wire = struct.pack("!H", len(body)) + body
    records.append({"send": wire.hex()})
    sock.sendall(wire)


def exact(size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        records.append({"recv": chunk.hex()})
        if not chunk:
            raise EOFError("Broker closed distribution connection")
        data += chunk
    return data


def frame():
    header = exact(2)
    body = exact(struct.unpack("!H", header)[0])
    records.append({"frame": (header + body).hex()})
    return body


try:
    name = b"native_probe@client"
    if request["legacy"]:
        send_frame(b"n" + struct.pack("!HI", 5, 0x7499C) + name)
    else:
        # Existing features plus HANDSHAKE_23, EXPORT_PTR_TAG, BIT_BINARIES;
        # no atom cache, fragments or alternative send opcodes are requested.
        send_frame(b"N" + struct.pack("!QIH", 0x1074F9C, 0, len(name)) + name)
    status = frame()
    if status == b"snot_allowed":
        raise PermissionError("Broker refused distribution capabilities")
    assert status == b"sok", status
    challenge = frame()
    offset = 7 if challenge[:1] == b"n" else 9
    value = struct.unpack("!I", challenge[offset:offset + 4])[0]
    our_challenge = 0x12345678
    digest = hashlib.md5((request["cookie"] + str(value)).encode()).digest()
    send_frame(b"r" + struct.pack("!I", our_challenge) + digest)
    ack = frame()
    expected = b"a" + hashlib.md5((request["cookie"] + str(our_challenge)).encode()).digest()
    assert ack == expected, ack
    result = {"authenticated": True, "challenge_tag": challenge[:1].decode()}
except (EOFError, ConnectionResetError, PermissionError, socket.timeout) as error:
    result = {"authenticated": False, "error": type(error).__name__, "detail": str(error)}
finally:
    sock.close()
result["records"] = records
print(json.dumps(result))
