import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

// JDBC controls bypass the owning module and its web-query implementation.
public class NativeControl {
  private static void emit(String name, String value) {
    System.out.println(name + "=" + Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8)));
  }
  public static void main(String[] args) throws Exception {
    String action = args[0];
    String user = args.length > 1 ? args[1] : "sa";
    String password = user.equals("sa") ? "module-target-admin" : "module-target-reader";
    try (Connection connection = DriverManager.getConnection("jdbc:h2:tcp://127.0.0.1:9092/./state/known", user, password);
         Statement statement = connection.createStatement()) {
      if (action.equals("query")) {
        try (ResultSet rows = statement.executeQuery(args[2])) {
          while (rows.next()) {
            StringBuilder line = new StringBuilder();
            for (int index = 1; index <= rows.getMetaData().getColumnCount(); index++) {
              if (index > 1) line.append("\t");
              line.append(rows.getString(index));
            }
            emit("ROW", line.toString());
          }
        }
      } else if (action.equals("proof")) {
        String path = "/tmp/module-target-h2-native-proof";
        if (Files.exists(Paths.get(path))) throw new IllegalStateException("Stale native proof");
        boolean created = false;
        try {
          statement.execute("CREATE ALIAS MODULE_NATIVE_PROOF AS $$ String proof() throws Exception { Process process = new ProcessBuilder(\"/bin/sh\", \"-c\", \"printf module-target-native-h2 > " + path + "\").start(); if (process.waitFor() != 0) throw new IllegalStateException(); return \"native-h2\"; } $$");
          created = true;
          statement.execute("CALL MODULE_NATIVE_PROOF()");
          emit("PROOF", new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8));
        } catch (SQLException error) {
          if (user.equals("sa")) throw error;
          emit("DENIED", error.getErrorCode() + ":" + error.getMessage());
          if (error.getErrorCode() != 90040) throw error;
          if (Files.exists(Paths.get(path))) throw new IllegalStateException("Restricted alias executed");
        } finally {
          if (created) statement.execute("DROP ALIAS MODULE_NATIVE_PROOF");
          Files.deleteIfExists(Paths.get(path));
        }
      } else {
        throw new IllegalArgumentException("Unknown native action");
      }
    }
  }
}
