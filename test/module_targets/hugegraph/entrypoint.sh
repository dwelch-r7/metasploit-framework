#!/bin/bash
set -euo pipefail
if [[ ${1:-} == health ]]; then
  args=()
  if [[ ${HG_AUTH:-none} == config ]]; then args=(-u admin:module-target-admin); fi
  exec curl --fail --silent "${args[@]}" -H 'Content-Type: application/json' -d '{"gremlin":"1+1","bindings":{},"language":"gremlin-groovy","aliases":{}}' "http://127.0.0.1:8080${HG_PREFIX:-}/gremlin"
fi
mkdir -p /tmp/module-target-hugegraph
sha256sum lib/*.jar > /tmp/module-target-hugegraph/original-jars.sha256
cp conf/graphs/hugegraph.properties /tmp/module-target-hugegraph/original-graph.properties
cp conf/rest-server.properties /tmp/module-target-hugegraph/original-rest.properties
cp conf/gremlin-server.yaml /tmp/module-target-hugegraph/original-gremlin.yaml
if [[ ${HG_BACKEND:-memory} == memory ]]; then
  sed -i 's/^backend=.*/backend=memory/; s/^serializer=.*/serializer=text/' conf/graphs/hugegraph.properties
fi
sed -i "s#^restserver.url=.*#restserver.url=http://0.0.0.0:8080${HG_PREFIX:-}/#" conf/rest-server.properties
printf '\ngremlinPool: 2\nthreadPoolWorker: 2\nthreadPoolBoss: 1\n' >> conf/gremlin-server.yaml
if [[ ${HG_AUTH:-none} == config ]]; then
  # ConfigAuthenticator has no AuthManager RPC service; standalone HTTP mode
  # is selected through the vendor's documented empty-host RPC switch.
  sed -i 's/^rpc.server_host=.*/rpc.server_host=/' conf/rest-server.properties
  sed -i 's/^gremlin.graph=.*/gremlin.graph=org.apache.hugegraph.auth.HugeFactoryAuthProxy/' conf/graphs/hugegraph.properties
  printf '\nauth.authenticator=org.apache.hugegraph.auth.ConfigAuthenticator\nauth.admin_token=module-target-admin\n' >> conf/rest-server.properties
  cat >> conf/gremlin-server.yaml <<'YAML'
authentication: {
  authenticator: org.apache.hugegraph.auth.ConfigAuthenticator,
  authenticationHandler: org.apache.hugegraph.auth.WsAndHttpBasicAuthHandler,
  config: {tokens: conf/rest-server.properties}
}
YAML
fi
if [[ ${HG_BACKEND:-memory} == rocksdb ]]; then
  bin/init-store.sh
fi
exec bin/hugegraph-server.sh conf/gremlin-server.yaml conf/rest-server.properties true
