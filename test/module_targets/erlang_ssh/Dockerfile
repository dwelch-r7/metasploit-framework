ARG ERLANG_IMAGE=erlang:27.3.2-slim@sha256:eb71f4d1c00ef759d72b2160655c02bd74888713e9e47bed49532da2fe3edd8d
FROM ${ERLANG_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 1000 module_target && useradd --uid 1000 --gid 1000 --no-create-home --home-dir /tmp/module-target-erlang --shell /bin/sh module_target
COPY test/module_targets/erlang_ssh/server.escript test/module_targets/erlang_ssh/native.escript /opt/module-target/
ENTRYPOINT ["escript", "/opt/module-target/server.escript"]
