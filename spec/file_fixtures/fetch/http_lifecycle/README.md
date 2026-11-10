# Fetch lifecycle response capture

resource.txt is the exact benign body returned by the genuine Fetch HTTP
handler during the original Linux fetch-single-repeat / 0-started control.
The resource was registered through the real adapter setup method and read
with Net::HTTP; it is plain marker data, not executable code.

The read-only capture set is fetch-http-lifecycle-original-20261110-b4e90307c4b,
under tmp/fetch-http-lifecycle/linux-original-four/original-controls.json.
The later nine-scenario controls use Framework-generated, never-executed
exit(0) ELF resources and preserve full response bytes as base64 plus hashes.
The lifecycle regressions reuse the small text capture; the second-owner suffix
is an explicitly derived distinct body for the ownership-collision boundary.

To reproduce the captured resource, configure a local Fetch HTTP adapter with
@srv_resources = [{uri: 'fetch-0', data: "BENIGN_FETCH_RESOURCE:fetch-0\n",
opts: {dynamic_arch: false}}], call its real setup_handler, and request
/fetch-0 before cleanup. No payload execution or external target is required.
