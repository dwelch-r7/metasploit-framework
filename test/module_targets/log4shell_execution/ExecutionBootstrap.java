import java.lang.management.ManagementFactory;

/** Identifies the real gadget libraries loaded by the same HTTP target JVM. */
public final class ExecutionBootstrap {
  public static void main(String[] arguments) throws Exception {
    if (arguments.length == 0) {
      StringBuilder value = new StringBuilder("EXECUTION_TARGET_BOOT={\"pid\":\"")
        .append(ManagementFactory.getRuntimeMXBean().getName().split("@")[0]).append("\"");
      Class<?>[] classes = {org.apache.commons.beanutils.BeanComparator.class, org.apache.commons.collections.comparators.ComparableComparator.class, org.apache.commons.logging.Log.class};
      String[] names = {"beanutils", "collections", "logging"};
      for (int index = 0; index < classes.length; index++) {
        value.append(",\"").append(names[index]).append("_source\":\"")
          .append(classes[index].getProtectionDomain().getCodeSource().getLocation()).append("\"");
        value.append(",\"").append(names[index]).append("_version\":\"")
          .append(classes[index].getPackage().getImplementationVersion()).append("\"");
      }
      value.append(",\"trust_serial_data\":\"").append(System.getProperty("com.sun.jndi.ldap.object.trustSerialData")).append("\"}");
      System.out.println(value.toString());
    }
    Target.main(arguments);
  }
}
