# n8n fixed workflow-expression control

Use the serial command and independent controls in
[the shared recipe](../n8n_expression/README.md). This profile pins n8n 1.120.4,
which must still evaluate the ordinary IIFE but reject unsafe `mainModule`
access without writing a proof. It then requires the actual module's Safe result
and repeated AutoCheck refusal on one selection. This fix is specific to the
workflow-expression issue; it does not reuse another n8n CVE's fixed boundary.
