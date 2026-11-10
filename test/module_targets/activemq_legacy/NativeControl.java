import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.Session;
import javax.jms.TextMessage;
import org.apache.activemq.ActiveMQConnection;
import org.apache.activemq.ActiveMQConnectionFactory;
import org.apache.activemq.command.ActiveMQDestination;

// Use each distribution's actual JMS client and broker; no replacement protocol.
public class NativeControl {
  public static void main(String[] arguments) throws Exception {
    if (arguments.length != 1 || !(arguments[0].equals("info") || arguments[0].equals("jms"))) {
      throw new IllegalArgumentException("Expected info or jms");
    }
    ActiveMQConnectionFactory factory = new ActiveMQConnectionFactory("tcp://127.0.0.1:61616");
    ActiveMQConnection connection = (ActiveMQConnection) factory.createConnection();
    try {
      connection.start();
      System.out.println("PROVIDER_NAME=" + connection.getMetaData().getJMSProviderName());
      System.out.println("PROVIDER_VERSION=" + connection.getMetaData().getProviderVersion());
      System.out.println("BROKER_NAME=" + connection.getBrokerName());
      if (arguments[0].equals("jms")) {
        Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
        ActiveMQDestination queue = (ActiveMQDestination) session.createQueue("MODULE.TARGET.LEGACY.NATIVE");
        MessageProducer producer = session.createProducer(queue);
        MessageConsumer consumer = session.createConsumer(queue);
        producer.send(session.createTextMessage("module-target-legacy-native"));
        Message message = consumer.receive(3000);
        if (!(message instanceof TextMessage) || !((TextMessage) message).getText().equals("module-target-legacy-native")) {
          throw new IllegalStateException("Native JMS roundtrip did not match");
        }
        consumer.close();
        producer.close();
        session.close();
        connection.destroyDestination(queue);
        System.out.println("JMS_ROUNDTRIP=matched");
        System.out.println("JMS_DESTINATION_REMOVED=true");
      }
    } finally {
      connection.close();
    }
  }
}
