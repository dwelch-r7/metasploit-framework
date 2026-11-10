package metasploit;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

// A source-provided harmless classloader proof, executed only by the real JSP.
public class Payload {
  public static void main(String[] arguments) throws Exception {
    String path = "/tmp/module-target-native-legacy-jar";
    if (Files.exists(Paths.get(path))) throw new IllegalStateException("Proof is not fresh");
    Process child = new ProcessBuilder("/bin/sh", "-c", "printf '%s' \"$PPID\" > " + path).start();
    if (!child.waitFor(3, TimeUnit.SECONDS) || child.exitValue() != 0) {
      throw new IllegalStateException("Native JAR command did not complete");
    }
  }
}
