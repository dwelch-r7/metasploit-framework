import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;
import javax.script.ScriptEngineManager;
import org.pytorch.serve.archive.utils.ArchiveUtils;

/** Invoke ordinary JDK loading and the exact installed vendor YAML reader. */
public final class NativeProbe {
    public static void main(String[] args) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("mode", args[0]);
        result.put("pid", ProcessHandle.current().pid());
        result.put("user", System.getProperty("user.name"));
        result.put("java", System.getProperty("java.version"));
        result.put("vendor", ArchiveUtils.class.getProtectionDomain().getCodeSource().getLocation().toString());
        try {
            if (args[0].equals("constructor")) {
                try (URLClassLoader loader = new URLClassLoader(new URL[]{new URL(args[1])})) {
                    Object value = Class.forName("NativeScriptEngineFactory", true, loader).getDeclaredConstructor().newInstance();
                    result.put("class", value.getClass().getName());
                }
            } else if (args[0].equals("service")) {
                try (URLClassLoader loader = new URLClassLoader(new URL[]{new URL(args[1])})) {
                    ScriptEngineManager manager = new ScriptEngineManager(loader);
                    result.put("factories", manager.getEngineFactories().size());
                }
            } else if (args[0].equals("yaml")) {
                result.put("value", ArchiveUtils.readYamlFile(new File(args[1])));
            } else {
                throw new IllegalArgumentException("Unsupported native mode");
            }
            result.put("completed", true);
        } catch (Exception error) {
            result.put("completed", false);
            List<Map<String, String>> errors = new ArrayList<>();
            for (Throwable cause = error; cause != null; cause = cause.getCause()) {
                Map<String, String> entry = new LinkedHashMap<>();
                entry.put("type", cause.getClass().getName());
                entry.put("message", cause.getMessage());
                errors.add(entry);
            }
            result.put("errors", errors);
        }
        System.out.println(ArchiveUtils.GSON.toJson(result));
    }
}
