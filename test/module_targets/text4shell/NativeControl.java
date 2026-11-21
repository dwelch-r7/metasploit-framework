import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import org.apache.commons.text.StringSubstitutor;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Native engine/interpolator controls; the original HTTP controller is separate. */
public class NativeControl {
    public static void main(String[] args) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        result.put("java_version", System.getProperty("java.version"));
        result.put("text_version", StringSubstitutor.class.getPackage().getImplementationVersion());
        result.put("script_engine", engine == null ? null : engine.getFactory().getEngineName());
        try {
            if (!args[0].equals("metadata")) {
                String input = new String(Base64.getDecoder().decode(args[1]), StandardCharsets.UTF_8);
                Object value;
                if (args[0].equals("engine")) {
                    value = engine.eval(input);
                } else if (args[0].equals("interpolate")) {
                    value = StringSubstitutor.createInterpolator().replace(input);
                } else {
                    throw new IllegalArgumentException("Unknown native operation");
                }
                result.put("value", String.valueOf(value));
            }
            result.put("ok", true);
        } catch (RuntimeException | javax.script.ScriptException error) {
            result.put("ok", false);
            result.put("error_class", error.getClass().getName());
            result.put("error", error.getMessage());
        }
        System.out.println(new ObjectMapper().writeValueAsString(result));
    }
}
