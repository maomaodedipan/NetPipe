import java.net.*;
import java.io.*;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<usercertname>");
        System.err.println(indent + "--cacert=<cacertname>");
        System.err.println(indent + "--key=<keyname>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "usercertname");
        arguments.setArgumentSpec("cacert", "cacertname");
        arguments.setArgumentSpec("key", "keyname");
        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) throws Exception{
        Socket socket = null;

        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        ClientHandshake clientHandshake;
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }
        clientHandshake = new ClientHandshake(socket,arguments);
        try {
//            Forwarder.forwardStreams(System.in, System.out, socket.getInputStream(), socket.getOutputStream(), socket);
            Forwarder.forwardStreams(System.in,System.out,clientHandshake.sessionDecrypter.openDecryptedInputStream(socket.getInputStream()),clientHandshake.sessionEncrypter.openEncryptedOutputStream(socket.getOutputStream()),socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}
