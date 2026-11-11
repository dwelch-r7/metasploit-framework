import com.alibaba.fastjson.JSON;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.UUID;
import org.apache.rocketmq.common.MQVersion;
import org.apache.rocketmq.remoting.netty.NettyClientConfig;
import org.apache.rocketmq.remoting.netty.NettyRemotingClient;
import org.apache.rocketmq.remoting.protocol.RemotingCommand;

/** Native distribution SDK controls, independent of Framework's framing/parser. */
public final class NativeProbe {
    private final NettyRemotingClient client;

    private NativeProbe() {
        System.setProperty("rocketmq.remoting.version", Integer.toString(MQVersion.CURRENT_VERSION));
        NettyClientConfig config = new NettyClientConfig();
        config.setClientWorkerThreads(1);
        config.setClientCallbackExecutorThreads(1);
        client = new NettyRemotingClient(config);
        client.start();
    }

    private int code(String name) throws Exception {
        // The project's protocol classes moved packages between these releases.
        Class<?> type;
        try {
            type = Class.forName("org.apache.rocketmq.remoting.protocol.RequestCode");
        } catch (ClassNotFoundException absent) {
            type = Class.forName("org.apache.rocketmq.common.protocol.RequestCode");
        }
        return type.getField(name).getInt(null);
    }

    private RemotingCommand request(String endpoint, String name, byte[] body, String topic) throws Exception {
        RemotingCommand command = RemotingCommand.createRequestCommand(code(name), null);
        if (topic != null) command.addExtField("topic", topic);
        command.setBody(body);
        return client.invokeSync(endpoint, command, 5000);
    }

    private Map<String, Object> response(RemotingCommand reply) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("code", reply.getCode());
        data.put("remark", reply.getRemark());
        data.put("version_id", reply.getVersion());
        data.put("version", MQVersion.getVersionDesc(reply.getVersion()));
        data.put("body", reply.getBody() == null ? null : new String(reply.getBody(), StandardCharsets.UTF_8));
        return data;
    }

    private Properties config() throws Exception {
        RemotingCommand reply = request("127.0.0.1:10921", "GET_BROKER_CONFIG", null, null);
        if (reply.getCode() != 0 || reply.getBody() == null) throw new IllegalStateException("GET_BROKER_CONFIG: " + reply);
        Properties properties = new Properties();
        properties.load(new ByteArrayInputStream(reply.getBody()));
        return properties;
    }

    private Map<String, Object> update(Properties properties) throws Exception {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        properties.store(body, "Native SDK lab control");
        return response(request("127.0.0.1:10921", "UPDATE_BROKER_CONFIG", body.toByteArray(), null));
    }

    private Map<String, Object> snapshot() throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        RemotingCommand route = request("127.0.0.1:9876", "GET_ROUTEINFO_BY_TOPIC", null, "TBW102");
        if (route.getCode() != 0 || route.getBody() == null) throw new IllegalStateException("GET_ROUTEINFO_BY_TOPIC: " + route);
        Object data = JSON.parse(new String(route.getBody(), StandardCharsets.UTF_8));
        if (!JSON.toJSONString(data).contains(":10921")) throw new IllegalStateException("Broker not registered on nondefault port: " + data);
        result.put("route", response(route));
        result.put("route_data", data);
        result.put("config", new TreeMap<>(config()));
        result.put("client_version", MQVersion.getVersionDesc(MQVersion.CURRENT_VERSION));
        result.put("uid", Files.getAttribute(Paths.get("/proc/self"), "unix:uid"));
        result.put("broker_pid", new String(Files.readAllBytes(Paths.get("/tmp/module-target-rocketmq/broker.pid")), StandardCharsets.UTF_8).trim());
        return result;
    }

    private Map<String, Object> control() throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        Properties before = config();
        result.put("before", snapshot());
        Properties noop = new Properties();
        noop.setProperty("brokerName", before.getProperty("brokerName"));
        result.put("allowed_noop_update", update(noop));
        Path marker = Paths.get("/tmp/module-target-native-" + UUID.randomUUID().toString().replace("-", ""));
        if (Files.exists(marker)) throw new IllegalStateException("Marker unexpectedly exists");
        String value = "ROCKETMQ_NATIVE_" + UUID.randomUUID().toString().replace("-", "");
        result.put("marker", marker.toString());
        Properties injection = new Properties();
        injection.setProperty("filterServerNums", "1");
        injection.setProperty("rocketmqHome", "-c $@|sh . echo printf " + value + " > " + marker + ";#");
        try {
            result.put("injected_update", update(injection));
            long deadline = System.nanoTime() + 36000000000L;
            while (!Files.exists(marker) && System.nanoTime() < deadline) Thread.sleep(200);
            boolean executed = Files.exists(marker);
            result.put("executed", executed);
            if (executed) {
                String actual = new String(Files.readAllBytes(marker), StandardCharsets.UTF_8);
                if (!value.equals(actual)) throw new IllegalStateException("Incorrect marker contents: " + actual);
                result.put("marker_uid", Files.getAttribute(marker, "unix:uid"));
                result.put("marker_value", actual);
            }
            boolean expected = System.getenv("ROCKETMQ_VERSION").equals("4.9.4");
            if (executed != expected) throw new IllegalStateException("Native execution disagrees with expected release behavior: " + executed);
        } finally {
            Properties restore = new Properties();
            restore.setProperty("filterServerNums", before.getProperty("filterServerNums"));
            restore.setProperty("rocketmqHome", before.getProperty("rocketmqHome"));
            result.put("restore", update(restore));
            Files.deleteIfExists(marker);
        }
        Properties after = config();
        if (!before.equals(after)) throw new IllegalStateException("Native control did not restore logical config");
        result.put("logical_config_restored", true);
        result.put("marker_absent", !Files.exists(marker));
        result.put("after", snapshot());
        result.put("status", "native_passed");
        return result;
    }

    public static void main(String[] args) throws Exception {
        NativeProbe probe = new NativeProbe();
        try {
            Object result;
            if (args[0].equals("control")) {
                result = probe.control();
            } else if (args[0].equals("restore")) {
                // Recovery is a visible native SDK operation, never an owning
                // module success. Session tests assert state before using it.
                Properties properties = new Properties();
                properties.setProperty("rocketmqHome", args[1]);
                properties.setProperty("filterServerNums", args[2]);
                Map<String, Object> restored = new LinkedHashMap<>();
                restored.put("update", probe.update(properties));
                restored.put("snapshot", probe.snapshot());
                result = restored;
            } else {
                result = probe.snapshot();
            }
            System.out.println("NATIVE_JSON=" + JSON.toJSONString(result));
        } finally {
            probe.client.shutdown();
        }
    }
}
