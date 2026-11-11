import java.net.URI;
import java.rmi.registry.LocateRegistry;
import java.nio.charset.StandardCharsets;

public final class LabHealth {
  public static void main(String[] args) throws Exception {
    LocateRegistry.getRegistry("127.0.0.1", LabConfig.REGISTRY).list();
    var connection = URI.create("http://127.0.0.1:" + LabConfig.HTTP + "/health").toURL().openConnection();
    connection.setConnectTimeout(2000);
    connection.setReadTimeout(2000);
    try (var input = connection.getInputStream()) {
      String body = new String(input.readAllBytes(), StandardCharsets.UTF_8);
      if (!body.equals("MODULE_TARGET_RMI:" + System.getenv("LAB_ROLE"))) throw new IllegalStateException(body);
    }
  }
}
