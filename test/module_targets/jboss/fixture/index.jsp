<%@ page import="java.lang.management.ManagementFactory" %><% response.setContentType("text/plain"); %>module-target-jboss-native
account=<%= System.getProperty("user.name") %>
java=<%= System.getProperty("java.version") %>
server=<%= application.getServerInfo() %>
