import java.io.*;
import java.lang.instrument.*;
import java.lang.management.ManagementFactory;
import java.net.URL;
import java.security.*;
import java.util.*;

/** Passive provenance only: never alters class bytes, methods or application state. */
public final class IdentityAgent {
  private static String output;
  private static final Set<String> SEEN = new HashSet<>();
  private static final Set<String> WANTED = new HashSet<>(Arrays.asList(
    "org/apache/logging/log4j/core/lookup/JndiLookup", "org/apache/naming/factory/BeanFactory",
    "org/apache/naming/ResourceRef", "javax/el/ELProcessor"));
  private static String quote(String value) {
    if (value == null) return "null";
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\"";
  }
  private static String hex(byte[] bytes) {
    StringBuilder text = new StringBuilder();
    for (byte value : bytes) text.append(String.format("%02x", value & 255));
    return text.toString();
  }
  private static String digest(File file) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (InputStream input = new FileInputStream(file)) {
      byte[] buffer = new byte[65536]; int count;
      while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
    }
    return hex(digest.digest());
  }
  private static synchronized void record(String row) throws IOException {
    try (Writer writer = new OutputStreamWriter(new FileOutputStream(output, true), "UTF-8")) { writer.write(row + "\n"); }
  }
  public static void premain(String path, Instrumentation instrumentation) throws Exception {
    output = path;
    // Initialize standard hashing/IO before observing application class loading.
    MessageDigest.getInstance("SHA-256").digest(new byte[0]);
    record("{\"kind\":\"jvm\",\"pid\":" + quote(ManagementFactory.getRuntimeMXBean().getName().split("@")[0]) +
      ",\"java_version\":" + quote(System.getProperty("java.version")) + ",\"java_vendor\":" + quote(System.getProperty("java.vendor")) +
      ",\"os_arch\":" + quote(System.getProperty("os.arch")) + ",\"url_codebase\":" + quote(System.getProperty("com.sun.jndi.ldap.object.trustURLCodebase")) +
      ",\"serial_data\":" + quote(System.getProperty("com.sun.jndi.ldap.object.trustSerialData")) + "}");
    instrumentation.addTransformer(new ClassFileTransformer() {
      public byte[] transform(ClassLoader loader, String name, Class<?> previous, ProtectionDomain domain, byte[] bytes) {
        if (!WANTED.contains(name)) return null;
        synchronized (SEEN) { if (!SEEN.add(name)) return null; }
        try {
          URL source = domain.getCodeSource().getLocation();
          record("{\"kind\":\"class\",\"name\":" + quote(name) + ",\"source\":" + quote(source.toString()) +
            ",\"jar_sha256\":" + quote(digest(new File(source.toURI()))) +
            ",\"class_sha256\":" + quote(hex(MessageDigest.getInstance("SHA-256").digest(bytes))) + "}");
        } catch (Exception error) {
          try { record("{\"kind\":\"observer_error\",\"error\":" + quote(error.toString()) + "}"); } catch (IOException ignored) { System.err.println("Module target identity observer could not write its error"); }
        }
        return null;
      }
    });
  }
}
