import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

public final class LabState implements LabStateMBean {
  public String getRole() { return System.getenv("LAB_ROLE"); }
  @SuppressWarnings("removal")
  public String getLoaderPolicy() {
    return "securityManager=" + (System.getSecurityManager() != null)
      + ";useCodebaseOnly=" + System.getProperty("java.rmi.server.useCodebaseOnly", "true")
      + ";dgcFilter=" + System.getProperty("sun.rmi.transport.dgcFilter", "default")
      + ";serverCodebase=" + System.getProperty("java.rmi.server.codebase", "none");
  }
  public String[] getProofs() throws Exception {
    try (Stream<Path> paths = Files.list(Path.of("/tmp"))) {
      return paths.map(path -> path.getFileName().toString())
        .filter(name -> name.startsWith("module-target-java-proof-")).sorted().toArray(String[]::new);
    }
  }
  public String readProof(String token) throws Exception {
    Path path = LabConfig.proof(token);
    return Files.exists(path) ? Files.readString(path) : "ABSENT";
  }
  public boolean removeProof(String token) throws Exception {
    Path path = LabConfig.proof(token);
    String value = readProof(token);
    if (!value.equals("ABSENT") && !value.startsWith("MODULE_TARGET_JAVA_PROOF:" + token + ":"))
      throw new IllegalStateException("Unexpected proof contents");
    Files.deleteIfExists(path);
    return !Files.exists(path);
  }
}
