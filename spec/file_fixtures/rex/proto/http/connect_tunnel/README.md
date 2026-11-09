# Native HTTP CONNECT framing

`captures.json` contains exact request/header bytes and base64-encoded body
bytes from digest-pinned Apache 2.4.62 with genuine mod_proxy_http and
mod_proxy_connect. A separate origin supports real HTTP and HTTPS. The retained
producer uses Ruby Socket and captures complete wire headers independently of
Rex; source and producer checksums identify its unmodified local evidence.

Two native successful CONNECT replies have no HTTP body framing. Native
permission/method/unavailable-service refusals retain their actual body bytes.
Ordinary GET and HEAD captures provide controls for unchanged framing behavior.
Additional 2xx codes, forbidden length/transfer headers, coalesced tunnel data,
fragmentation, reset/reuse, malformed status lines and HTML metadata are
explicitly derived robustness cases.

[RFC 9110 section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
requires a successful CONNECT response to switch to a tunnel after its headers,
with length and transfer fields ignored for framing. Bytes following those
headers belong to that tunnel rather than an HTTP response body.
