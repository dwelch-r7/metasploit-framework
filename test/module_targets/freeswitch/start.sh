#!/bin/sh
set -eu
: "${FREESWITCH_PASSWORD:=ClueCon}"
: "${FREESWITCH_ACL:=0.0.0.0/0}"
if [ "${1:-}" = health ]; then
 exec fs_cli -p "$FREESWITCH_PASSWORD" -x "module_exists mod_event_socket"
fi
sha256sum -c /lab/binaries.sha256
cat > /usr/local/freeswitch/conf/autoload_configs/event_socket.conf.xml <<EOF
<configuration name="event_socket.conf" description="Owned event-socket lab">
 <settings>
  <param name="nat-map" value="false"/>
  <param name="listen-ip" value="0.0.0.0"/>
  <param name="listen-port" value="8021"/>
  <param name="password" value="$FREESWITCH_PASSWORD"/>
  <param name="apply-inbound-acl" value="module_target_esl"/>
 </settings>
</configuration>
EOF
cat > /usr/local/freeswitch/conf/autoload_configs/acl.conf.xml <<EOF
<configuration name="acl.conf" description="Owned event-socket lab">
 <network-lists><list name="module_target_esl" default="deny">
  <node type="allow" cidr="$FREESWITCH_ACL"/>
 </list></network-lists>
</configuration>
EOF
printf '%s\n' "$$" > /tmp/module-target-engine.pid
exec freeswitch -nf -nonat
