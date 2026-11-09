#!/bin/sh
set -eu

# The vendor's JSP servlet supports Ant/javac through its documented compiler
# and fork options. Its bundled old JDT cannot read Java 8 CharSequence.
deployer=/opt/jboss/server/default/deploy/jboss-web.deployer
ln -sf /opt/module-target/compiler/ant.jar "$deployer/ant.jar"
ln -sf /opt/module-target/compiler/ant-launcher.jar "$deployer/ant-launcher.jar"
settings='<init-param><param-name>compiler</param-name><param-value>javac1.8</param-value></init-param><init-param><param-name>compilerTargetVM</param-name><param-value>1.5</param-value></init-param>'
sed -i "s|<servlet-class>org.apache.jasper.servlet.JspServlet</servlet-class>|<servlet-class>org.apache.jasper.servlet.JspServlet</servlet-class>$settings|" "$deployer/conf/web.xml"
sed -i '/<param-name>fork<\/param-name>/{n;s|<param-value>false</param-value>|<param-value>true</param-value>|;}' "$deployer/conf/web.xml"
exec /opt/module-target/start.sh
