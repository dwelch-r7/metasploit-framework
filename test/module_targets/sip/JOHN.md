# Optional native John interoperability control

Routine SIP cases remain short and do not compile John. Their literal capture
fixtures were independently verified with official John source commit
`37bebbe4b6442c8dd3888e5848ef062c0783e9f3` (SIP self-test passed). Reproduce the
known artificial password recovery from the four actual client datagrams:

```sh
mkdir -p tmp/sip-john-native/output
curl --fail --location https://codeload.github.com/openwall/john/tar.gz/37bebbe4b6442c8dd3888e5848ef062c0783e9f3 -o tmp/sip-john-native/john-37bebbe.tar.gz
printf '%s  %s\n' 9e595c25610de6dd3fa37124c57a1be76548399bb299f285d6797e60d3efb969 tmp/sip-john-native/john-37bebbe.tar.gz | shasum -a 256 -c -
docker build -t module-target-sip-john:37bebbe -f test/module_targets/sip/john.Dockerfile tmp/sip-john-native
printf '%s\n' module-target-sip-password > tmp/sip-john-native/output/wordlist.txt
docker run --rm --network none --read-only --cap-drop ALL --tmpfs /tmp:rw,nosuid,nodev,size=16m -v "$PWD/spec/file_fixtures/modules/auxiliary/sip:/fixtures:ro" -v "$PWD/tmp/sip-john-native/output:/output:rw" module-target-sip-john:37bebbe --format=SIP --session=/output/native --pot=/output/native.pot --wordlist=/output/wordlist.txt /fixtures/capture_auth.john
docker run --rm --network none --read-only --cap-drop ALL --tmpfs /tmp:rw,nosuid,nodev,size=16m -v "$PWD/spec/file_fixtures/modules/auxiliary/sip:/fixtures:ro" -v "$PWD/tmp/sip-john-native/output:/output:rw" module-target-sip-john:37bebbe --format=SIP --show --pot=/output/native.pot /fixtures/capture_auth.john
```

Expected: four captured records recovered, zero left (two unique hashes).
Use a fresh output/pot path for a new independent recovery. `--session` points
John's log at the owned writable output; its source tree stays read-only.
The source archive is verified and no Framework dependency is installed.

The [pinned format implementation](https://github.com/openwall/john/blob/37bebbe4b6442c8dd3888e5848ef062c0783e9f3/src/sip_fmt_plug.c)
uses 14 star separators, including three URI components: scheme, resource and
port/suffix (empty when absent). It reconstructs those components before MD5.
The original module and initial test oracle omitted one field and were rejected
by the real parser. Those original files and the fixture error are retained.
A valid-format counterfactual using SIPp's request URI recovered only two of four
records; its signed Authorization URI includes a port. The corrected actual URI
recovers all four. A separate exact upstream qop=auth vector recovered its public
password `abc`; qop live-client capture remains outside the current server profile.
