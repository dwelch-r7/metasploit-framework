FROM couchdb:3.3.1@sha256:04d9b3ef9406112a9903484fbbaf1497e1b5fce892bd214e1135565ab97aa48b

COPY --chown=couchdb:couchdb single-node.ini /opt/couchdb/etc/local.d/module-target.ini
ENV COUCHDB_USER=labadmin COUCHDB_PASSWORD=labpassword ERL_FLAGS="+S 2:2 +A 4"
