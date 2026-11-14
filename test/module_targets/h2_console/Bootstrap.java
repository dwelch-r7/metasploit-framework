import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import org.h2.tools.Server;

// Both listeners are genuine H2 web servers; their database-creation policy differs.
public class Bootstrap {
  public static void main(String[] args) throws Exception {
    Class.forName("org.h2.Driver");
    try (Connection connection = DriverManager.getConnection("jdbc:h2:./state/known", "sa", "module-target-admin");
         Statement statement = connection.createStatement()) {
      statement.execute("CREATE USER IF NOT EXISTS reader PASSWORD 'module-target-reader'");
      statement.execute("CREATE TABLE IF NOT EXISTS MODULE_CANARY(ID INT PRIMARY KEY, VALUE_TEXT VARCHAR)");
      statement.execute("MERGE INTO MODULE_CANARY KEY(ID) VALUES(1, 'module-target-h2-canary')");
      statement.execute("GRANT SELECT ON MODULE_CANARY TO reader");
    }
    Server.createTcpServer("-tcpPort", "9092", "-tcpAllowOthers", "-ifNotExists").start();
    Server.createWebServer("-webPort", "8082", "-webAllowOthers", "-ifNotExists", "-properties", "null").start();
    Server.createWebServer("-webPort", "8083", "-webAllowOthers", "-ifExists", "-properties", "null").start();
    System.out.println("MODULE_TARGET_H2_READY");
  }
}
