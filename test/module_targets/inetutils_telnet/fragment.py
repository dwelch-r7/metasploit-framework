"""Forward genuine telnetd bytes unchanged, splitting server writes on purpose."""
import base64, json, socket, threading, time
from pathlib import Path

logs = Path('/tmp/module-target-framing')
logs.mkdir(exist_ok=True)


def bridge(client, number):
    upstream = socket.create_connection(('127.0.0.1', 23), 3)
    upstream.settimeout(None)
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    streams = {'client':bytearray(),'server':bytearray()}
    errors = []

    def forward(source, target, direction):
        try:
            while True:
                block = source.recv(8192)
                if not block:
                    break
                streams[direction].extend(block)
                if direction == 'server':
                    for value in block:
                        target.sendall(bytes([value]))
                        # Deliberate test transport fragmentation, not readiness
                        # polling: TCP permits arbitrary byte boundaries.
                        time.sleep(.002)
                else:
                    target.sendall(block)
        except OSError as error:
            errors.append({'direction':direction,'type':type(error).__name__,'errno':error.errno})
        finally:
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass
    worker = threading.Thread(target=forward,args=(client,upstream,'client'))
    worker.start()
    forward(upstream,client,'server')
    worker.join(5)
    client.close()
    upstream.close()
    (logs/(str(number)+'.json')).write_text(json.dumps({'streams':{k:base64.b64encode(v).decode()for k,v in streams.items()},'errors':errors})+'\n')


with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    listener.bind(('0.0.0.0',2323))
    listener.listen(8)
    number=0
    while True:
        client,_address=listener.accept()
        number+=1
        threading.Thread(target=bridge,args=(client,number),daemon=True).start()
