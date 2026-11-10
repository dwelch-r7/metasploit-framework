# Genuine NiFi credential gathering through native sessions

Run `bundle exec ruby tools/dev/run_module_target_tests.rb nifi_credentials`.
Host Docker, Python3, Node with built-in crypto and the normal Framework bundle
are required; no npm or new Framework dependencies are used.

The target extends the pinned stock Apache NiFi 1.21.0 image with Python3 for
native ELF launching. Its actual application still runs the original vendor
script as NiFi UID1000. Native controls compare vendor runtime/startup/H2 bytes,
verify real UI/API versions, authentication and the public fixture account, then
create real stored configuration through NiFi's API. A real GetHTTP processor
authenticates to Apache; real generated PKCS12 stores are inspected by keytool.
Other disabled database/Azure configurations are stored secret controls, not
claims that external cloud/database credentials authenticate.

The flow's actual encrypted fields are independently decrypted with Node's
built-in PBKDF2/AES-GCM and compared with the native configured plaintext.
No replacement API, invented ciphertext or simulated session is used. A native
vendor id ELF first checks launcher UID behavior; later real generated shell
and Linux Meterpreter payloads prove sessions and actual commands as the NiFi
service user. Root success and labuser refusal are separate paths.

The public NIFI_PATH points to the official container's actual
`/opt/nifi/nifi-current`, since the module defaults describe another layout.
Exact properties/flow bytes, decrypted loot, native component graphs and
independent SQL session/workspace origins are checked on repeated read paths.
Private, missing, identity-only, missing-key, unsupported-algorithm and corrupt
GCM-tag copies are explicit derived file/parser boundary cases made from genuine
vendor files. They are not claimed to be accepted running NiFi configurations.
The private copy has native UID1000/0700 policy, with independently denied
labuser reads. The actual live files remain unchanged by these counterfactuals.

Fixture ELF/proof files are removed explicitly and target services are disposed
with all owned volumes. Native live-file and API graph equality precedes the
final explicitly labelled GetHTTP canary replay. Other NiFi versions, operating
systems, Azure authentication and Azure authorizer-file branches are unqualified.
