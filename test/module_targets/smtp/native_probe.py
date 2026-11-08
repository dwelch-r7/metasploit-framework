"""Verify real Exim recipient handling without delivering outside the lab."""
import os
import smtplib
import sys

profile = os.environ["SMTP_PROFILE"]
with smtplib.SMTP("127.0.0.1", 25, timeout=3) as client:
    code, banner = client.helo("native.module-target.test")
    assert code == 250 and b"smtp.module-target.test" in banner, (code, banner)
    code, reply = client.verify("root")
    assert code == (250 if profile in ("vrfy", "open_relay") else 252), (code, reply)
    code, reply = client.verify("module_target")
    assert code == (250 if profile in ("vrfy", "open_relay") else 252), (code, reply)
    code, reply = client.verify("module_target_missing")
    assert code == (550 if profile in ("vrfy", "open_relay") else 252), (code, reply)
    assert client.mail("native@sender.example.test")[0] == 250
    code, reply = client.rcpt("module_target@smtp.module-target.test")
    assert code == 250, (code, reply)
    client.rset()
    assert client.mail("native@sender.example.test")[0] == 250
    code, reply = client.rcpt("module_target_missing@smtp.module-target.test")
    assert code == (250 if profile == "catchall" else 550), (code, reply)
    client.rset()
    assert client.mail("native@sender.example.test")[0] == 250
    code, reply = client.rcpt("sink@recipient.example.test")
    assert code == (250 if profile == "open_relay" else 550), (code, reply)
    if profile == "open_relay" and sys.argv[1:] != ["--health"]:
        code, reply = client.data("Subject: Native module target proof\r\n\r\nnative-smtp-proof\r\n")
        assert code == 250, (code, reply)

print("Native SMTP verification, recipients and relay policy verified:", profile)
