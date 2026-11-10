# Native Prometheus captures

Captured by native-prometheus.json from original-source run
20261109T235710-83dfde, using the pinned genuine lab in
test/module_targets/prometheus. Both API YAML files are exact returned bytes;
inline secrets are redacted by Prometheus. Metric files contain only the
unaltered sample line for the actual quoted volume mount, selected from the
full native metrics response. Prometheus ingested and decoded these labels
independently through PromQL; device/mount fields were checked against actual
kernel files. No provider metadata or HTTP response was synthesized.

SHA256:

- old-api-config.yml: f2caa5ce2bf4f1e71c67b187fd081cd88244eff09100e5c8a0cf103ff4b4861a
- modern-api-config.yml: 4161004c6033eb1a11b7a60d8f775ffad0e70096e004b708c5e94286e912b503
- node-quoted-filesystem.txt: b90dfdee2c3c53ff0bbb637258978ee4bf27e4c6f991255ef88f066d5688ceef
- node_legacy-quoted-filesystem.txt: 7657203769f1edb0e95fffad51d6ea92b318dc20aa862a1acb1b458a944d04ea

The focused spec labels substituted authentication fields and the documented
escape-string example as derived cases. They do not claim that a static
password was returned by the native API, or that the exporter produced
every documented escaping form.
