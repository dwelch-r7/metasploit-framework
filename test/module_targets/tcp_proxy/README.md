# Native TCP transport controls

This component provides the official pinned Toxiproxy 2.9.0 server. A consuming
family extends `proxy`, publishes its own loopback data port, and configures the
actual upstream and toxic through the native HTTP API before module execution.
It does not replace the upstream service or invent service replies.

The component's control port is randomly mapped to loopback; data ports and
upstream policy belong to the consuming family. Native controls must verify
complete upstream content through the altered transport and record the applied
configuration. Source: [pinned Toxiproxy documentation](https://github.com/Shopify/toxiproxy/blob/v2.9.0/README.md).
