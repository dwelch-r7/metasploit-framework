"""Independent stdlib mail clients; no Framework protocol/parser dependencies."""

import base64
import hashlib
import imaplib
import json
import os
import poplib
import ssl
import subprocess
import sys


runtime = json.load(open(os.environ["MODULE_TARGET_RUNTIME"], encoding="utf-8"))
commands = []
profiles = {}
read_only = "--read-only" in sys.argv
username = "module_target"
password = "module-target-password"
marker = b"Native mail body: module-target-mailbox-proof"
SOCKET_TIMEOUT = 5
AUTH_TIMEOUT = 20


def native(service, *arguments):
    result = subprocess.run(
        runtime["compose"] + ["exec", "-T", service] + list(arguments),
        capture_output=True, text=True, timeout=20, check=False,
    )
    commands.append({"service": service, "argv": arguments, "stdout": result.stdout,
                     "stderr": result.stderr, "exitstatus": result.returncode})
    if result.returncode:
        raise RuntimeError(f"Native command failed: {service} {arguments}: {result.stderr}")
    return result.stdout


def endpoint(service):
    value = runtime["endpoints"][service]
    return value["host"], value["port"]


def certificate_context(service):
    certificate = native(service, "cat", "/etc/dovecot/certificates/server.crt")
    return ssl.create_default_context(cadata=certificate)


def close_pop(client):
    try:
        client.quit()
    except (OSError, poplib.error_proto):
        client.close()


def pop_read(service, context=None, starttls=False):
    address, port = endpoint(service)
    if service == "pop3s":
        client = poplib.POP3_SSL(address, port, timeout=SOCKET_TIMEOUT, context=context)
    else:
        client = poplib.POP3(address, port, timeout=SOCKET_TIMEOUT)
    report = {"banner": client.getwelcome().decode("ascii")}
    try:
        if starttls:
            response = client.stls(context=context)
            report["starttls"] = response.decode("ascii")
        client.sock.settimeout(AUTH_TIMEOUT)
        client.user(username)
        report["login"] = client.pass_(password).decode("ascii")
        client.sock.settimeout(SOCKET_TIMEOUT)
        count, size = client.stat()
        if count != 1 or size <= len(marker):
            raise AssertionError(f"Unexpected POP3 mailbox size: {count}, {size}")
        _, lines, _ = client.retr(1)
        message = b"\n".join(lines)
        if marker not in message or b"<module-target-mailbox@example.test>" not in message:
            raise AssertionError(f"Native POP3 message differs: {message!r}")
        report.update(messages=count, message_base64=base64.b64encode(message).decode("ascii"),
                      message_sha256=hashlib.sha256(message).hexdigest())
        return report
    finally:
        close_pop(client)


def pop_reject(service, candidate_user, candidate_password, context=None):
    address, port = endpoint(service)
    client = (poplib.POP3_SSL(address, port, timeout=SOCKET_TIMEOUT, context=context)
              if service == "pop3s" else poplib.POP3(address, port, timeout=SOCKET_TIMEOUT))
    try:
        # Dovecot's per-IP failure penalty can reach fifteen seconds.
        # Keep connects/readback short, but await the real auth decision.
        client.sock.settimeout(AUTH_TIMEOUT)
        try:
            client.user(candidate_user)
            response = client.pass_(candidate_password)
        except poplib.error_proto as error:
            response = error.args[0]
            if not response.startswith(b"-ERR"):
                raise
            return response.decode("ascii")
        raise AssertionError(f"Native POP3 unexpectedly accepted {candidate_user!r}: {response!r}")
    finally:
        close_pop(client)


def imap_read(service, context=None):
    address, port = endpoint(service)
    client = (imaplib.IMAP4_SSL(address, port, ssl_context=context, timeout=SOCKET_TIMEOUT)
              if service == "imaps" else imaplib.IMAP4(address, port, timeout=SOCKET_TIMEOUT))
    report = {"banner": client.welcome.decode("ascii")}
    try:
        client.sock.settimeout(AUTH_TIMEOUT)
        status, _ = client.login(username, password)
        if status != "OK":
            raise AssertionError(f"Native IMAP login failed: {status}")
        client.sock.settimeout(SOCKET_TIMEOUT)
        status, values = client.select("INBOX", readonly=True)
        if status != "OK" or values != [b"1"]:
            raise AssertionError(f"Native IMAP mailbox differs: {status}, {values!r}")
        status, data = client.fetch("1", "(BODY.PEEK[])")
        message = b"".join(item[1] for item in data if isinstance(item, tuple))
        if status != "OK" or marker not in message or b"<module-target-mailbox@example.test>" not in message:
            raise AssertionError(f"Native IMAP message differs: {status}, {data!r}")
        report.update(messages=1, message_base64=base64.b64encode(message).decode("ascii"),
                      message_sha256=hashlib.sha256(message).hexdigest())
        return report
    finally:
        client.logout()


try:
    for service in ("pop3", "pop3s", "imap", "imaps", "required"):
        version = native(service, "dovecot", "--version").strip()
        if not version.startswith("2.3.16 "):
            raise AssertionError(f"Unexpected native Dovecot version: {version}")
        config = "/etc/dovecot/required.conf" if service == "required" else "/etc/dovecot/dovecot.conf"
        native(service, "doveconf", "-c", config, "-n")
        native(service, "dpkg-query", "-W", "dovecot-core", "dovecot-pop3d", "dovecot-imapd", "openssl")
        context = certificate_context(service) if service in ("pop3s", "imaps", "required") else None
        if service in ("imap", "imaps"):
            profiles[service] = imap_read(service, context)
        else:
            if service == "required" and not read_only:
                rejection = pop_reject(service, username, password)
                if "TLS" not in rejection and "secure" not in rejection:
                    raise AssertionError(f"Expected a TLS policy refusal: {rejection}")
                profiles[service] = {"cleartext_rejection": rejection}
            else:
                profiles[service] = {}
            profiles[service].update(pop_read(service, context, starttls=service == "required"))
            if service != "required" and not read_only:
                profiles[service]["rejections"] = {
                    "wrong_password": pop_reject(service, username, "wrong-password", context),
                    "unknown_user": pop_reject(service, "missing-user", password, context),
                    "blank_password": pop_reject(service, username, "", context),
                }
        profiles[service]["version"] = version
finally:
    print(json.dumps({"profiles": profiles, "commands": commands}, indent=2))
