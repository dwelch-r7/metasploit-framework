<%@ page import="java.io.File" %><%
response.setContentType("text/plain");
File active = new File("/tmp/module-target-jboss-active");
File release = new File("/tmp/module-target-jboss-release");
active.createNewFile();
try {
  long deadline = System.currentTimeMillis() + 30000;
  while (!release.exists() && System.currentTimeMillis() < deadline) Thread.sleep(50);
  out.print("module-target-jboss-held-request");
} finally {
  active.delete();
}
%>
