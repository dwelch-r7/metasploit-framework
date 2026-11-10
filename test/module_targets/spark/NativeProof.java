import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Harmless standalone driver proving actual driver execution and identity. */
public class NativeProof {
    public static void main(String[] args) throws Exception {
        String identity = System.getProperty("user.name") + "\n" + System.getProperty("java.version") + "\n";
        Files.write(Paths.get(args[0]), identity.getBytes(StandardCharsets.UTF_8));
        System.out.println("MODULE_TARGET_NATIVE_DRIVER=" + identity.replace('\n', ':'));
    }
}
