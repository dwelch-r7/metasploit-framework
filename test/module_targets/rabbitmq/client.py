"""Independent Pika AMQP client; no Framework protocol implementation is used."""
import json
import logging
import socket
import ssl
import struct
import sys

import pika

logging.disable(logging.CRITICAL)
request = json.load(sys.stdin)
context = None
if request["tls"]:
    context = ssl.create_default_context(cadata=request["ca"])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
parameters = pika.ConnectionParameters(
    host=request["host"], port=5671 if context else 5672,
    virtual_host=request["vhost"],
    credentials=pika.PlainCredentials(request["username"], request["password"]),
    ssl_options=pika.SSLOptions(context, "localhost") if context else None,
    socket_timeout=5, stack_timeout=8, connection_attempts=1, heartbeat=0,
)
# Decode the actual unauthenticated connection.start with the independent client
# library, retaining its exact native bytes and advertised mechanisms.
with socket.create_connection((request["host"], parameters.port), timeout=5) as plain:
    stream = context.wrap_socket(plain, server_hostname="localhost") if context else plain

    def exact(size):
        data = b""
        while len(data) < size:
            chunk = stream.recv(size - len(data))
            if not chunk:
                raise EOFError("Broker closed before connection.start")
            data += chunk
        return data

    stream.sendall(b"AMQP\x00\x00\x09\x01")
    header = exact(7)
    body_size = struct.unpack("!BHI", header)[2]
    wire = header + exact(body_size + 1)
    _, decoded = pika.frame.decode_frame(wire)
    start = {"wire": wire.hex(), "mechanisms": decoded.method.mechanisms.decode("ascii")}
    if context:
        start["tls"] = stream.version()
        start["cipher"] = stream.cipher()
        stream.close()
try:
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    queue = channel.queue_declare(queue="", exclusive=True, auto_delete=True).method.queue
    channel.basic_publish(exchange="", routing_key=queue, body=b"module-target-native-amqp")
    method, _, body = channel.basic_get(queue=queue, auto_ack=True)
    assert body == b"module-target-native-amqp" and method.message_count == 0
    properties = connection._impl.server_properties
    connection.close()
    result = {"connected": True, "roundtrip": body.decode(), "properties": properties}
except (pika.exceptions.ProbableAuthenticationError, pika.exceptions.ProbableAccessDeniedError) as error:
    result = {"connected": False, "error": type(error).__name__, "detail": str(error)}
result["start"] = start
print(json.dumps(result))
