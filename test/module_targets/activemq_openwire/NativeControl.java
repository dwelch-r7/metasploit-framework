import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Collections;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.jms.Connection;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.Session;
import javax.jms.TextMessage;
import com.sun.net.httpserver.HttpServer;
import org.apache.activemq.ActiveMQConnection;
import org.apache.activemq.ActiveMQConnectionFactory;
import org.apache.activemq.command.ActiveMQDestination;
import org.apache.activemq.command.WireFormatInfo;
import org.apache.activemq.openwire.OpenWireFormat;
import org.apache.activemq.util.ByteSequence;

// Uses the genuine vendor JMS client/decoder and broker. The HTTP listener only
// supplies a proof XML document; it never executes commands or replaces a broker.
public class NativeControl {
  private static void binary(String key, byte[] value) {
    System.out.println(key + "=" + Base64.getEncoder().encodeToString(value));
  }

  private static void greeting(Socket socket) throws Exception {
    DataInputStream input = new DataInputStream(socket.getInputStream());
    int length = input.readInt();
    if (length < 1 || length > 8192) throw new IllegalStateException("Invalid greeting length");
    byte[] body = new byte[length];
    input.readFully(body);
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    DataOutputStream frame = new DataOutputStream(bytes);
    frame.writeInt(length);
    frame.write(body);
    binary("OPENWIRE_FRAME_BASE64", bytes.toByteArray());
    Object value = new OpenWireFormat().unmarshal(new ByteSequence(bytes.toByteArray()));
    if (!(value instanceof WireFormatInfo)) throw new IllegalStateException("Not WireFormatInfo");
    WireFormatInfo info = (WireFormatInfo) value;
    System.out.println("OPENWIRE_NAME=" + info.getProperties().get("ProviderName"));
    System.out.println("OPENWIRE_VERSION=" + info.getProperties().get("ProviderVersion"));
    System.out.println("OPENWIRE_PROTOCOL=" + info.getVersion());
    binary("OPENWIRE_PROPERTIES_BASE64", info.getProperties().toString().getBytes(StandardCharsets.UTF_8));
  }

  private static void jms() throws Exception {
    ActiveMQConnectionFactory factory = new ActiveMQConnectionFactory("tcp://127.0.0.1:61616");
    ActiveMQConnection connection = (ActiveMQConnection) factory.createConnection();
    try {
      connection.start();
      Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
      ActiveMQDestination queue = (ActiveMQDestination) session.createQueue("MODULE.TARGET.NATIVE");
      MessageProducer producer = session.createProducer(queue);
      MessageConsumer consumer = session.createConsumer(queue);
      producer.send(session.createTextMessage("module-target-native-roundtrip"));
      Message message = consumer.receive(3000);
      if (!(message instanceof TextMessage) || !((TextMessage) message).getText().equals("module-target-native-roundtrip")) {
        throw new IllegalStateException("Native JMS message mismatch");
      }
      System.out.println("JMS_BROKER=" + connection.getBrokerName());
      System.out.println("JMS_ROUNDTRIP=matched");
      consumer.close();
      producer.close();
      session.close();
      connection.destroyDestination(queue);
      System.out.println("JMS_DESTINATION_REMOVED=true");
    } finally {
      connection.close();
    }
  }

  private static void openwire(Path proof) throws Exception {
    if (!proof.toString().matches("/tmp/module-target-native-openwire-[0-9]+") || Files.exists(proof)) {
      throw new IllegalArgumentException("Proof path must be fresh and within the native fixture namespace");
    }
    String command = "printf '%s' \"$PPID\" > " + proof;
    String xml = """
      <?xml version="1.0" encoding="UTF-8"?>
      <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
       <bean id="nativeProof" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg><list><value>/bin/sh</value><value>-c</value><value><![CDATA[%s]]></value></list></constructor-arg>
       </bean>
      </beans>
      """.formatted(command);
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
    try (Socket socket = new Socket("127.0.0.1", 61616)) {
      socket.setSoTimeout(3000);
      greeting(socket);
      String uri = "http://127.0.0.1:" + server.getAddress().getPort() + "/native.xml";
      ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      DataOutputStream body = new DataOutputStream(bytes);
      // Vendor ExceptionResponse -> Response -> BaseCommand, then loose Throwable.
      // DataOutputStream.writeUTF supplies the actual unsigned 16-bit ASCII lengths.
      body.writeByte(31);
      body.writeInt(0);
      body.writeBoolean(false);
      body.writeInt(0);
      body.writeBoolean(true);
      body.writeBoolean(true);
      body.writeUTF("org.springframework.context.support.ClassPathXmlApplicationContext");
      body.writeBoolean(true);
      body.writeUTF(uri);
      body.writeShort(0); // Empty stack trace.
      body.writeBoolean(false); // Null cause.
      DataOutputStream output = new DataOutputStream(socket.getOutputStream());
      output.writeInt(bytes.size());
      output.write(bytes.toByteArray());
      output.flush();
      binary("NATIVE_BODY_BASE64", bytes.toByteArray());
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

  public static void main(String[] args) throws Exception {
    if (args.length == 0) throw new IllegalArgumentException("Expected info, jms or openwire");
    switch (args[0]) {
      case "info":
        try (Socket socket = new Socket("127.0.0.1", 61616)) {
          socket.setSoTimeout(3000);
          greeting(socket);
        }
        break;
      case "jms": jms(); break;
      case "openwire": openwire(Path.of(args[1])); break;
      default: throw new IllegalArgumentException("Unknown native control mode");
    }
  }
}
