import com.sun.net.httpserver.HttpServer;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import javax.management.ObjectName;

public final class Main {
  private static Registry registry;
  private static Registry multi;
  private static LabEchoImpl echo;
  public static void main(String[] args) throws Exception {
    String role = System.getenv("LAB_ROLE");
    ManagementFactory.getPlatformMBeanServer().registerMBean(new LabState(), new ObjectName(LabConfig.STATE));
    if (role.equals("empty")) {
      registry = LocateRegistry.createRegistry(LabConfig.REGISTRY);
      multi = LocateRegistry.createRegistry(LabConfig.MULTI);
      echo = new LabEchoImpl();
      multi.rebind("lab/echo", echo);
      multi.rebind("quoted café", echo);
    }
    HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", LabConfig.HTTP), 8);
    server.createContext("/health", exchange -> {
      byte[] body = ("MODULE_TARGET_RMI:" + role).getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, body.length);
      try (var output = exchange.getResponseBody()) { output.write(body); }
    });
    server.createContext("/probe.jar", exchange -> {
      byte[] body = Files.readAllBytes(Path.of("/lab/probe.jar"));
      exchange.sendResponseHeaders(200, body.length);
      try (var output = exchange.getResponseBody()) { output.write(body); }
    });
    server.setExecutor(Executors.newFixedThreadPool(2));
    server.start();
    System.out.println("MODULE_TARGET_JAVA_READY:" + role + ":" + System.getProperty("java.runtime.version"));
    new CountDownLatch(1).await();
  }
}
