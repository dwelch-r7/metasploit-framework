import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

// Readable, bounded marker code for native MLet/DGC calibration in owned JVMs.
// It accepts only a fresh token and writes no general command or external path.
public final class ProbePayload implements ProbePayloadMBean, Serializable {
  private static final long serialVersionUID = 1L;
  private String token;
  public ProbePayload() {}
  public ProbePayload(String value) { token = value; }
  @SuppressWarnings("removal")
  public String prove(String value) throws IOException {
    if (!value.matches("[0-9a-f]{32}")) throw new IllegalArgumentException("Invalid owned token");
    String proof = "MODULE_TARGET_JAVA_PROOF:" + value + ":PID=" + ProcessHandle.current().pid()
      + ":USER=" + System.getProperty("user.name");
    // The DGC dispatcher has a restricted calling context. Only the deliberately
    // permissive enabled-role policy grants this downloaded class its own write
    // permission; use that domain when proving actual deserialized execution.
    try {
      AccessController.doPrivileged((PrivilegedExceptionAction<Void>)() -> {
        Files.writeString(Path.of("/tmp/module-target-java-proof-" + value), proof, StandardOpenOption.CREATE_NEW);
        return null;
      });
    } catch (PrivilegedActionException error) {
      throw new IOException("Owned proof write failed", error.getException());
    }
    return proof;
  }
  private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
    input.defaultReadObject();
    prove(token);
  }
}
