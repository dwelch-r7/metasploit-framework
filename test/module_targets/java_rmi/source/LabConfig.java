import java.nio.file.Path;

public final class LabConfig {
  public static final int REGISTRY = Integer.parseInt(System.getenv("LAB_REGISTRY_PORT"));
  public static final int OBJECT = Integer.parseInt(System.getenv("LAB_OBJECT_PORT"));
  public static final int MULTI = Integer.parseInt(System.getenv("LAB_MULTI_PORT"));
  public static final int ECHO = Integer.parseInt(System.getenv("LAB_ECHO_PORT"));
  public static final int HTTP = Integer.parseInt(System.getenv("LAB_HTTP_PORT"));
  public static final String STATE = "module.target:type=State";
  public static Path proof(String token) {
    if (!token.matches("[0-9a-f]{32}")) throw new IllegalArgumentException("Invalid owned proof token");
    return Path.of("/tmp/module-target-java-proof-" + token);
  }
}
