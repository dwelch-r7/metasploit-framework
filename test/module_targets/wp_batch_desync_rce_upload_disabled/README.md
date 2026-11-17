# wp_batch_desync_rce_upload_disabled

See the [genuine RCE setup](../wp_batch_desync_rce/README.md).
This profile uses {"release": "6.9.4", "mode": "upload_disabled", "upload_disabled": true}.
Registration is not accepted runtime coverage.

The owned launcher writes the inherited core configuration plus the file-change
flag to the official image's `WORDPRESS_CONFIG_EXTRA_FILE`. Apache and independent
`docker exec` PHP controls therefore read the same setting. An entrypoint-only
environment change does not propagate to subsequent Docker exec processes.
