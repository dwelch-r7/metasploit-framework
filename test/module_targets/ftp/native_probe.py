"""Exercise the real FTP authentication, data channel and write permissions."""
import ftplib
import os
import sys


def connect(username, password):
    client = ftplib.FTP(timeout=3)
    banner = client.connect("127.0.0.1", 21)
    assert banner.startswith("220 "), banner
    client.login(username, password)
    return client


with connect("module_target", "module-target-password") as client:
    data = []
    client.retrbinary("RETR module-target.txt", data.append)
    assert b"".join(data) == b"module-target-ftp-marker\n"
    # Periodic health checks stay read-only while module tests exercise writes.
    if sys.argv[1:] == ["--health"]:
        print("Native FTP authentication and file content verified")
        sys.exit(0)
    client.mkd("native-local-proof")
    client.rmd("native-local-proof")

try:
    connect("module_target", "wrong-password")
except ftplib.error_perm as error:
    assert str(error).startswith("530 "), error
else:
    raise AssertionError("Invalid local password was accepted")

mode = os.environ["ANONYMOUS_MODE"]
try:
    anonymous = connect("anonymous", "module-target@example.test")
except ftplib.error_perm as error:
    assert mode == "denied" and str(error).startswith("530 "), error
else:
    assert mode != "denied", "Anonymous authentication was accepted"
    with anonymous:
        assert "module-target.txt" in anonymous.nlst()
        try:
            anonymous.mkd("native-anonymous-proof")
        except ftplib.error_perm as error:
            assert mode == "read_only" and str(error).startswith("550 "), error
        else:
            anonymous.rmd("native-anonymous-proof")
            assert mode == "read_write", "Anonymous write was accepted"

assert sorted(os.listdir("/srv/ftp")) == ["module-target.txt"]
print("Native FTP authentication, listing, content and permissions verified:", mode)
