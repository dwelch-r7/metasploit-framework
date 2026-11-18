# BentoML legacy runner target

See the [shared setup and coverage guide](../bentoml/README.md). This profile runs
BentoML 1.4.2's genuine `start-runner-server` CLI with a tiny NumPy absolute-value
model. Native prediction/serialization controls precede the owning module. Its
passive check returns Detected because the runner exposes no version check.
The 1.4.8 CLI removal is an unavailable target, with no runtime-safe runner claim.
