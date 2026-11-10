"""Independent wire checks for genuine database clients; never a protocol server."""
import hashlib
import struct


def mysql_packets(data):
    packets = []
    while data:
        if len(data) < 4:
            raise ValueError('Incomplete MySQL packet header')
        length = int.from_bytes(data[:3], 'little')
        if len(data) < length + 4:
            raise ValueError('Incomplete MySQL packet body')
        packets.append((data[3], data[4:4+length]))
        data = data[4+length:]
    return packets


def cstring(data, offset):
    end = data.index(b'\x00', offset)
    return data[offset:end], end + 1


def mysql_greeting(data):
    """Read Protocol::HandshakeV10 as documented by MySQL/MariaDB."""
    if data[0] != 10:
        raise ValueError('Not a protocol10 greeting')
    version, offset = cstring(data, 1)
    connection = int.from_bytes(data[offset:offset+4], 'little')
    first = data[offset+4:offset+12]
    offset += 13
    lower = int.from_bytes(data[offset:offset+2], 'little')
    offset += 2
    if len(data) == offset:
        return {'version': version.decode(), 'connection': connection, 'capabilities': lower, 'seed': first, 'plugin': None}
    charset = data[offset]
    status = int.from_bytes(data[offset+1:offset+3], 'little')
    upper = int.from_bytes(data[offset+3:offset+5], 'little')
    auth_length = data[offset+5]
    offset += 16
    second_length = max(13, auth_length - 8)
    second = data[offset:offset+second_length]
    offset += second_length
    seed = (first + second)[:20]
    plugin = data[offset:].split(b'\x00', 1)[0].decode('ascii') if upper & 8 else None
    return {'version': version.decode(), 'connection': connection, 'capabilities': lower | upper << 16, 'charset': charset, 'status': status, 'auth_length': auth_length, 'seed': seed, 'plugin': plugin}


def length_encoded(data, offset):
    first = data[offset]
    offset += 1
    if first < 0xfb:
        return first, offset
    size = {0xfc: 2, 0xfd: 3, 0xfe: 8}.get(first)
    if size is None:
        raise ValueError('Invalid length-encoded field')
    return int.from_bytes(data[offset:offset+size], 'little'), offset + size


def mysql_login(data):
    flags = int.from_bytes(data[:4], 'little')
    if len(data) == 32 and flags & 0x800:
        return {'ssl_request': True, 'flags': flags}
    if len(data) < 33:
        raise ValueError('Incomplete handshake response')
    user, offset = cstring(data, 32)
    if flags & (1 << 21):
        length, offset = length_encoded(data, offset)
        response, offset = data[offset:offset+length], offset + length
    elif flags & 0x8000:
        length = data[offset]
        offset += 1
        response, offset = data[offset:offset+length], offset + length
    else:
        response, offset = cstring(data, offset)
    database = None
    if flags & 8:
        database, offset = cstring(data, offset)
    plugin = None
    if flags & (1 << 19) and offset < len(data):
        plugin, offset = cstring(data, offset)
    return {'flags': flags, 'username': user.decode('utf-8'), 'response': response, 'database': database.decode('utf-8') if database is not None else None, 'plugin': plugin.decode('ascii') if plugin is not None else None}


def mysql_native_response(password, challenge):
    """MariaDB/MySQL native auth: SHA1(pw) XOR SHA1(seed+SHA1(SHA1(pw)))."""
    first = hashlib.sha1(password.encode('utf-8')).digest()
    mask = hashlib.sha1(challenge + hashlib.sha1(first).digest()).digest()
    return bytes(left ^ right for left, right in zip(first, mask))


def tds_packets(data):
    packets = []
    while data:
        if len(data) < 8:
            raise ValueError('Incomplete TDS header')
        kind, status, length, session, number, window = struct.unpack('!BBHHBB', data[:8])
        if length < 8 or len(data) < length:
            raise ValueError('Incomplete TDS body')
        packets.append({'type': kind, 'status': status, 'session': session, 'number': number, 'window': window, 'payload': data[8:length]})
        data = data[length:]
    return packets


def tds_login7(data):
    """MS-TDS2.2.6.4 offsets are relative to the start of LOGIN7 payload."""
    values = {}
    for name, position in [('host', 36), ('username', 40), ('password', 44), ('application', 48), ('server', 52), ('database', 68)]:
        offset, length = struct.unpack('<HH', data[position:position+4])
        raw = data[offset:offset+length*2]
        if len(raw) != length * 2:
            raise ValueError('LOGIN7 field exceeds payload')
        if name == 'password':
            raw = bytes((((value ^ 0xa5) & 0x0f) << 4) | (((value ^ 0xa5) & 0xf0) >> 4) for value in raw)
        values[name] = raw.decode('utf-16le')
    return values
