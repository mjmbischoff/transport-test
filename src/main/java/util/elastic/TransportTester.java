package util.elastic;

import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.cluster.health.ClusterIndexHealth;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.shield.ShieldPlugin;
import org.elasticsearch.transport.client.PreBuiltTransportClient;
import org.elasticsearch.xpack.client.PreBuiltXPackTransportClient;
import picocli.CommandLine;

import java.net.UnknownHostException;
import java.util.concurrent.Callable;

public class TransportTester implements Callable<Integer> {

    @CommandLine.Parameters(index = "0", description = "A Command (eg 'health')", defaultValue = "health")
    private String command;

    @CommandLine.Option(names = {"-a", "--address"}, description = "ip address of transport server", defaultValue = "127.0.0.1")
    private java.net.InetAddress transportAddress;

    @CommandLine.Option(names = {"-p", "--port"}, description = "transport port", defaultValue = "9300")
    private int transportPort;

    @CommandLine.Option(names = {"-c", "--clusterId"}, description = "clusterId (must also specify -u)")
    private String clusterId;

    @CommandLine.Option(names = {"-u", "--credentials"}, description = "username:password (only used when specifying clusterId)")
    private String usernamePassword;

    @CommandLine.Option(names = {"-x", "--xPack"}, description = "use xPack client", defaultValue = "true")
    private boolean xpack;

    @CommandLine.Option(names = {"-s", "--ssl"}, description = "use ssl", defaultValue = "true")
    private boolean enableSsl;

    @CommandLine.Option(names = {"-k", "--insecure"}, description = "Insecure", defaultValue = "false")
    private boolean insecure;

    @CommandLine.Option(names = {"--key"}, description = "/path/to/client.key")
    private String sslKey;

    @CommandLine.Option(names = {"--cert"}, description = "/path/to/client.crt")
    private String certificate;

    @CommandLine.Option(names = {"--ca"}, description = "/path/to/ca.crt")
    private String certificateAuthority;

    public static void main(String[] args) throws UnknownHostException {
        int exitCode = new CommandLine(new TransportTester()).execute(args);
        System.exit(exitCode);
    }

    public Integer call() throws Exception {
        try(TransportClient client = xpack ? createXPackClient() : createClient()) {

            switch (command) {
                case "health": return checkHealth(client);
                default:
                    System.out.println("unknown command '"+command+"'");
                    return -1;
            }

        }
    }

    // https://www.elastic.co/guide/en/elasticsearch/reference/6.8/java-clients.html
    private TransportClient createXPackClient() {
        // xpack translated example of https://www.elastic.co/guide/en/cloud-enterprise/current/security-transport.html
        if(clusterId!=null) {
            System.out.println("Using " + transportAddress + " port: "+ transportPort + "clusterId: "+clusterId);

            Settings.Builder builder = Settings.builder()
                    .put("transport.ping_schedule", "5s")
                    .put("transport.sniff", false)
                    .put("transport.tcp.compress", true);

            if(clusterId!=null) {
                builder
                    .put("cluster.name", clusterId)
                    .put("request.headers.X-Found-Cluster", clusterId);
            }

            builder
                //.put("action.bulk.compress", false)
                .put("xpack.security.transport.ssl.enabled", enableSsl)
                .put("xpack.security.transport.ssl.verification_mode", insecure ? "none" : "full");

            if(usernamePassword!=null) {
                builder.put("xpack.security.user", usernamePassword);
            }

            if(sslKey!=null) {
                builder.put("xpack.ssl.key", sslKey);
            }

            if(certificate!=null) {
                builder.put("xpack.ssl.certificate", certificate);
            }

            if(certificateAuthority!=null) {
                builder.put("xpack.ssl.certificate_authorities", certificateAuthority);
            }

            Settings settings = builder.build();

            return new PreBuiltXPackTransportClient(settings)
                    .addTransportAddress(new TransportAddress(transportAddress, transportPort));
        }

        System.out.println("Using " + transportAddress + " port: "+ transportPort);

        return new PreBuiltXPackTransportClient(Settings.EMPTY)
                .addTransportAddress(new TransportAddress(transportAddress, transportPort));
    }

    private TransportClient createClient() {
        // https://www.elastic.co/guide/en/cloud-enterprise/current/security-transport.html
        if(clusterId!=null) {
            System.out.println("Using " + transportAddress + " port: "+ transportPort + "clusterId: "+clusterId);

            Settings settings = Settings.builder()
                    .put("transport.ping_schedule", "5s")
                    //.put("transport.sniff", false) // Disabled by default and *must* be disabled.
                    .put("cluster.name", clusterId)
                    .put("action.bulk.compress", false)
                    .put("shield.transport.ssl", true)
                    .put("request.headers.X-Found-Cluster", clusterId)
                    .put("shield.user", usernamePassword) // your shield username and password
                    .build();

            return new PreBuiltTransportClient(settings, ShieldPlugin.class)
                    .addTransportAddress(new TransportAddress(transportAddress, transportPort));
        }

        System.out.println("Using " + transportAddress + " port: "+ transportPort);

        return new PreBuiltTransportClient(Settings.EMPTY)
                .addTransportAddress(new TransportAddress(transportAddress, transportPort));
    }

    private Integer checkHealth(TransportClient client) {
        System.out.println("requesting cluster health");
        ClusterHealthResponse healths = client.admin().cluster().prepareHealth().get();

        System.out.println("cluster name: " + healths.getClusterName());
        System.out.println("number of dataNodes: " + healths.getNumberOfDataNodes());
        System.out.println("number of nodes: " + healths.getNumberOfNodes());

        for (ClusterIndexHealth health : healths.getIndices().values()) {
            System.out.println("index: '" + health.getIndex() + "' numberOfShards = " + health.getNumberOfShards() + " numberOfReplicas = " + health.getNumberOfReplicas() + " status = " + health.getStatus());
        }

        return 0;
    }
}
