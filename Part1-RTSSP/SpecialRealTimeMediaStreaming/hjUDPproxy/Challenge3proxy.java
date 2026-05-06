/* hjUDPproxy, 20/Mar/18
 *
 * This is a very simple (transparent) UDP proxy
 * The proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

class Challenge3proxy {
    public static void main(String[] args) throws Exception {
        InputStream inputStream = new FileInputStream("config.properties");
        if (inputStream == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Properties properties = new Properties();
        properties.load(inputStream);
        String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

        //init crypto
        byte[] key = "streaming_key_32streaming_key_32".getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(key, "HmacSHA256");
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(skeySpec);

        DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[8 * 1024];

        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket);  // if remote is unicast

            //decryption

            ByteBuffer bb = ByteBuffer.wrap(inPacket.getData(), 0, inPacket.getLength()); //transform packet in byte buffer
            long receivedSeqNum = bb.getLong();
            short receivedSize = bb.getShort();
            byte[] receivedBytes = new byte[receivedSize];
            bb.get(receivedBytes); // extraction of video

            hmac.update(ByteBuffer.allocate(8).putLong(receivedSeqNum).array());
            byte[] keystream = hmac.doFinal(); // effective decryption

            for (int i = 0; i < receivedSize; i++) {
                receivedBytes[i] = (byte) (receivedBytes[i] ^ keystream[i % keystream.length]); // xor decryption
            }

            System.out.print(".");
            for (SocketAddress outSocketAddress : outSocketAddressSet)
            {
                outSocket.send(new DatagramPacket(receivedBytes, receivedBytes.length, outSocketAddress));
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress)
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
