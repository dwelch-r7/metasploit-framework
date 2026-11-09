#!/bin/sh
set -eu
# Vendor request logging retains real methods, queries, form parameters and
# responses without printing source-code strings into Framework's error guard.
sed -i 's|</Host>|<Valve className="org.apache.catalina.valves.RequestDumperValve" /></Host>|' /opt/jboss/server/default/deploy/jboss-web.deployer/server.xml
if [ "${LAB_POLICY:-open}" != open ]; then
  console=/opt/jboss/server/default/deploy/jmx-console.war/WEB-INF
  # Keep the authentic servlet and change only the vendor-documented policy.
  methods=''
  if [ "$LAB_POLICY" = legacy ]; then
    methods='<http-method>GET</http-method><http-method>POST</http-method>'
  fi
  constraint="<security-constraint><web-resource-collection><web-resource-name>Management</web-resource-name><url-pattern>/*</url-pattern>$methods</web-resource-collection><auth-constraint><role-name>JBossAdmin</role-name></auth-constraint></security-constraint>"
  sed -i "s|</web-app>|$constraint</web-app>|" "$console/web.xml"
  printf '%s\n' '<jboss-web><security-domain>java:/jaas/jmx-console</security-domain></jboss-web>' > "$console/jboss-web.xml"
  printf 'admin=%s\n' "${LAB_PASSWORD:-module-target-admin-password}" > /opt/jboss/server/default/conf/props/jmx-console-users.properties
  root=/opt/jboss/server/default/deploy/jboss-web.deployer/ROOT.war/WEB-INF
  status='<security-constraint><web-resource-collection><web-resource-name>Status</web-resource-name><url-pattern>/status</url-pattern></web-resource-collection><auth-constraint><role-name>JBossAdmin</role-name></auth-constraint></security-constraint><login-config><auth-method>BASIC</auth-method><realm-name>JBoss status</realm-name></login-config><security-role><role-name>JBossAdmin</role-name></security-role>'
  sed -i "s|</web-app>|$status</web-app>|" "$root/web.xml"
  cp "$console/jboss-web.xml" "$root/jboss-web.xml"
fi
exec /opt/jboss/bin/run.sh -b 0.0.0.0
