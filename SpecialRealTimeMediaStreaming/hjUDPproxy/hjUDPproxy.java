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

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.MulticastSocket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

class hjUDPproxy {
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

	DatagramSocket inSocket = new DatagramSocket(inSocketAddress); 
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024];

        SecretKeySpec key = new SecretKeySpec("streaming_key_16".getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket);  // if remote is unicast
            try {
                byte[] iv = new byte[12];
                System.arraycopy(inPacket.getData(), 0, iv, 0, iv.length); // we get the iv at the beggining of the packet

                int encryptedSize = inPacket.getLength() - iv.length;
                byte[] encryptedBytes = new byte[encryptedSize];
                System.arraycopy(inPacket.getData(), iv.length, encryptedBytes, 0, encryptedBytes.length); // we get the encrypted bytes at the end of the packet

                cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv)); //decrypt
                byte[] decryptedBytes = cipher.doFinal(encryptedBytes, 0, encryptedSize);

                System.out.print(".");
                for (SocketAddress outSocketAddress : outSocketAddressSet)
                {
                    DatagramPacket outPacket = new DatagramPacket(decryptedBytes, decryptedBytes.length, outSocketAddress);
                    outSocket.send(new DatagramPacket(decryptedBytes, outPacket.getLength(), outSocketAddress));
                }
                System.out.println("encryptedBytes:");
                String en = Base64.getEncoder().encodeToString(encryptedBytes);
                System.out.println(en);
                System.out.println("decryptedBytes:");
                String de = Base64.getEncoder().encodeToString(decryptedBytes);
                System.out.println(decryptedBytes);
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
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
