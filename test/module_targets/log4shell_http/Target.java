import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.Executors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.lookup.JavaLookup;

/** Genuine vendor logging sink; the loopback LDAP collector never serves objects. */
public final class Target {
  private static final Deque<Map<String,Object>> EVENTS = new ArrayDeque<>();
  private static long sequence;
  private static Logger logger;
  private static String mode;
  private static final String VERSION = System.getenv().getOrDefault("LOG4J_VERSION", "2.14.1");

  private static Map<String,Object> object(Object... values) {
    Map<String,Object> result = new LinkedHashMap<>();
    for (int index = 0; index < values.length; index += 2) result.put((String)values[index], values[index + 1]);
    return result;
  }

  private static String quote(String value) {
    StringBuilder result = new StringBuilder("\"");
    for (char character : value.toCharArray()) {
      switch (character) {
        case '\\': result.append("\\\\"); break;
        case '"': result.append("\\\""); break;
        case '\n': result.append("\\n"); break;
        case '\r': result.append("\\r"); break;
        case '\t': result.append("\\t"); break;
        default:
          if (character < 32) result.append(String.format("\\u%04x", (int)character));
          else result.append(character);
      }
    }
    return result.append('"').toString();
  }

  private static String json(Object value) {
    if (value == null) return "null";
    if (value instanceof Boolean || value instanceof Number) return value.toString();
    if (value instanceof Map) {
      List<String> fields = new ArrayList<>();
      for (Object item : ((Map<?,?>)value).entrySet()) {
        Map.Entry<?,?> field = (Map.Entry<?,?>)item;
        fields.add(quote(field.getKey().toString()) + ":" + json(field.getValue()));
      }
      return "{" + String.join(",", fields) + "}";
    }
    if (value instanceof Iterable) {
      List<String> fields = new ArrayList<>();
      for (Object item : (Iterable<?>)value) fields.add(json(item));
      return "[" + String.join(",", fields) + "]";
    }
    return quote(value.toString());
  }

  private static synchronized void record(Map<String,Object> event) {
    event.put("id", ++sequence);
    EVENTS.addLast(event);
    while (EVENTS.size() > 512) EVENTS.removeFirst();
  }

  private static synchronized Map<String,Object> events(long after) {
    List<Map<String,Object>> selected = new ArrayList<>();
    for (Map<String,Object> event : EVENTS) if ((Long)event.get("id") > after) selected.add(event);
    return object("sequence", sequence, "events", selected);
  }

  private static String digest(Path path) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] bytes = digest.digest(Files.readAllBytes(path));
    StringBuilder result = new StringBuilder();
    for (byte value : bytes) result.append(String.format("%02x", value & 255));
    return result.toString();
  }

  private static Map<String,Object> metadata() throws Exception {
    Map<String,Object> hashes = object();
    for (String artifact : new String[]{"log4j-api", "log4j-core"}) {
      String filename = artifact + "-" + VERSION + ".jar";
      hashes.put(filename, digest(Paths.get("vendor", filename)));
    }
    return object("version", VERSION, "mode", mode, "pid", ManagementFactory.getRuntimeMXBean().getName().split("@")[0],
      "java_version", System.getProperty("java.version"), "java_vendor", System.getProperty("java.vendor"),
      "java_os_lookup", new JavaLookup().lookup("os"), "implementation_version", LogManager.class.getPackage().getImplementationVersion(),
      "api_code_source", LogManager.class.getProtectionDomain().getCodeSource().getLocation().toString(),
      "core_code_source", org.apache.logging.log4j.core.LoggerContext.class.getProtectionDomain().getCodeSource().getLocation().toString(),
      "logger_class", logger == null ? "java.util.logging.Logger" : logger.getClass().getName(),
      "format_msg_no_lookups", System.getProperty("log4j2.formatMsgNoLookups"),
      "trust_url_codebase", System.getProperty("com.sun.jndi.ldap.object.trustURLCodebase"),
      "sentinel", System.getenv("MSF_MODULE_TARGET_LEAK"), "property_sentinel", System.getProperty("msf.module.target.value"),
      "jars", hashes);
  }

  private static Map<String,String> query(String raw) throws Exception {
    Map<String,String> result = new LinkedHashMap<>();
    if (raw != null) for (String item : raw.split("&")) {
      String[] pair = item.split("=", 2);
      result.put(URLDecoder.decode(pair[0], "UTF-8"), URLDecoder.decode(pair.length == 2 ? pair[1] : "", "UTF-8"));
    }
    return result;
  }

  private static void log(String point, String value) {
    if (value == null) return;
    record(object("kind", "logged_input", "point", point, "value", value));
    if (logger == null) java.util.logging.Logger.getLogger("module-target").info(value);
    else logger.info(value);
  }

  private static void http(HttpExchange exchange) throws IOException {
    try {
      String path = exchange.getRequestURI().getPath();
      Map<String,String> parameters = query(exchange.getRequestURI().getRawQuery());
      Map<String,Object> response;
      if (path.equals("/health") || path.equals("/meta")) response = metadata();
      else if (path.equals("/events")) response = events(Long.parseLong(parameters.getOrDefault("after", "0")));
      else {
        record(object("kind", "http_request", "method", exchange.getRequestMethod(), "raw_uri", exchange.getRequestURI().toASCIIString(), "decoded_path", path));
        if (path.startsWith("/header/")) {
          for (String header : new String[]{"User-Agent", "X-Log4j-Input"}) log("header:" + header, exchange.getRequestHeaders().getFirst(header));
        } else if (path.startsWith("/path/")) log("path", path);
        else if (path.startsWith("/query/")) log("query", parameters.get("q"));
        else if (path.equals("/native-log")) log("native", parameters.get("value"));
        response = object("received", true, "method", exchange.getRequestMethod());
      }
      byte[] bytes = json(response).getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
      exchange.sendResponseHeaders(200, bytes.length);
      exchange.getResponseBody().write(bytes);
    } catch (Exception error) {
      record(object("kind", "http_error", "error", error.toString()));
      exchange.sendResponseHeaders(500, -1);
    } finally { exchange.close(); }
  }

  private static byte[] readExactly(InputStream input, int length) throws IOException {
    byte[] value = new byte[length]; int offset = 0;
    while (offset < length) { int count = input.read(value, offset, length - offset); if (count < 0) throw new EOFException(); offset += count; }
    return value;
  }

  private static int length(InputStream input) throws IOException {
    int value = input.read(); if (value < 0) throw new EOFException();
    if (value < 128) return value;
    int count = value & 127; if (count == 0 || count > 3) throw new IOException("Unsupported BER length");
    value = 0;
    for (byte item : readExactly(input, count)) value = (value << 8) | (item & 255);
    if (value > 65536) throw new IOException("LDAP message exceeds collector bound");
    return value;
  }

  private static byte[] tlv(int tag, byte[] body) throws IOException {
    ByteArrayOutputStream result = new ByteArrayOutputStream(); result.write(tag);
    if (body.length < 128) result.write(body.length);
    else if (body.length < 256) { result.write(129); result.write(body.length); }
    else { result.write(130); result.write(body.length >> 8); result.write(body.length); }
    result.write(body); return result.toByteArray();
  }

  /** RFC4511 sections4.1,4.2,4.5: bind success and empty SearchResultDone only. */
  private static void ldap(Socket socket) {
    try (Socket client = socket) {
      client.setSoTimeout(5000); InputStream input = client.getInputStream();
      while (true) {
        int tag = input.read(); if (tag < 0) return;
        if (tag != 48) throw new IOException("Expected LDAP message sequence");
        byte[] body = readExactly(input, length(input)); ByteArrayInputStream fields = new ByteArrayInputStream(body);
        if (fields.read() != 2) throw new IOException("Expected LDAP message ID");
        byte[] identifier = readExactly(fields, length(fields)); int operation = fields.read(); byte[] request = readExactly(fields, length(fields));
        Map<String,Object> event = object("kind", "native_ldap", "operation", operation, "peer", client.getRemoteSocketAddress().toString(), "request_base64", Base64.getEncoder().encodeToString(tlv(48, body)));
        if (operation == 99) {
          ByteArrayInputStream search = new ByteArrayInputStream(request);
          if (search.read() != 4) throw new IOException("Expected LDAP search base DN");
          event.put("base_dn", new String(readExactly(search, length(search)), StandardCharsets.UTF_8));
        }
        if (operation == 66) { record(event); return; }
        if (operation != 96 && operation != 99) throw new IOException("Unsupported native collector operation");
        ByteArrayOutputStream response = new ByteArrayOutputStream(); response.write(tlv(2, identifier));
        response.write(tlv(operation == 96 ? 97 : 101, new byte[]{10,1,0,4,0,4,0}));
        byte[] encoded = tlv(48, response.toByteArray()); event.put("response_base64", Base64.getEncoder().encodeToString(encoded));
        record(event); client.getOutputStream().write(encoded); client.getOutputStream().flush();
      }
    } catch (Exception error) { record(object("kind", "collector_error", "error", error.toString())); }
  }

  public static void main(String[] arguments) throws Exception {
    if (arguments.length == 1 && arguments[0].equals("health")) {
      HttpURLConnection connection = (HttpURLConnection)new URL("http://127.0.0.1:8080/health").openConnection();
      connection.setConnectTimeout(1000); connection.setReadTimeout(2000);
      if (connection.getResponseCode() != 200) throw new IOException("HTTP target is not healthy");
      connection.disconnect(); return;
    }
    mode = System.getenv().getOrDefault("LOG4J_MODE", "log4j");
    if (!Arrays.asList("log4j", "disabled", "jul").contains(mode)) throw new IllegalArgumentException("Unknown logging mode");
    if (mode.equals("disabled")) System.setProperty("log4j2.formatMsgNoLookups", "true");
    if (!mode.equals("jul")) logger = LogManager.getLogger("module-target");
    final ServerSocket collector = new ServerSocket(8389, 8, InetAddress.getByName("127.0.0.1"));
    Thread thread = new Thread(() -> { while (true) { try { ldap(collector.accept()); } catch (IOException error) { record(object("kind", "collector_error", "error", error.toString())); } } }, "native-ldap-collector");
    thread.setDaemon(true); thread.start();
    HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 8);
    server.createContext("/", Target::http); server.setExecutor(Executors.newFixedThreadPool(2)); server.start();
    System.out.println("LOG4J_TARGET_BOOT=" + json(metadata()));
  }
}
