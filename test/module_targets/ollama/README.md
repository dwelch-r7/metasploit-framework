# Genuine Ollama model enumeration

```sh
nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ollama
```

Three containers are capped at 1,856 MiB/1.6 CPUs. A pinned genuine Ollama 0.1.48
image imports a digest-verified 87.5 MiB SmolLM GGUF through the vendor CLI.
Native inference produces one real CPU token with a 128-token context, one worker
and no GPU device. Readable Modelfiles supply real model metadata; no API response
or installed/running catalog is simulated. Binary model weights are downloaded
from the vendor registry during the build and are not checked into this repo.

Apache supplies ordinary public/prefixed proxy routes, real Basic authentication
for all routes or only model details, and unrelated HTTP content. All host
bindings are random loopback ports. The Framework uses the internal network.
No volume or model state survives teardown.

Native CLI/API checks precede owning calls and run again afterward. Twelve owning
cases retain repeated installed/running/empty states, metadata fields, multiline
system prompts, authentication, prefixed URLs, unrelated HTTP and closed ports.
Native state-changing examples restore the two-model/running baseline afterward.
Call-through HTTP observations retain actual replies without Authorization values.
Configuration and native success alone do not qualify the Framework module.

Source references: [versioned API](https://github.com/ollama/ollama/blob/v0.1.48/docs/api.md),
[Modelfile format](https://github.com/ollama/ollama/blob/v0.1.48/docs/modelfile.md),
[official image build](https://github.com/ollama/ollama/blob/v0.1.48/Dockerfile),
and [SmolLM model](https://ollama.com/library/smollm:135m).
Other Ollama releases and GPU inference remain separate qualifications.

Observed results and preserved failures are recorded in [the verification report](../VERIFICATION-20261111-ollama.md).
