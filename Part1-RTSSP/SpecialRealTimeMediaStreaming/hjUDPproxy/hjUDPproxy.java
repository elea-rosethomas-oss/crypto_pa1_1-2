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

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

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
		byte[] buffer = new byte[8 * 1024];
		Map<String, CryptoConfig> cryptoConfigs = CryptoConfig.loadAll();

		while (true) {
			DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
			inSocket.receive(inPacket);  // if remote is unicast

			int len = inPacket.getLength();
			byte[] packetData = Arrays.copyOf(inPacket.getData(), len);
			EncryptedPacket encryptedPacket = EncryptedPacket.parse(packetData, cryptoConfigs);
			if (encryptedPacket == null) {
				continue;
			}
			CryptoConfig cryptoConfig = encryptedPacket.cryptoConfig;
			if (!encryptedPacket.hasValidMac()) {
				continue;
			}

			Cipher cipher = Cipher.getInstance(cryptoConfig.ciphersuite);
			AlgorithmParameterSpec spec = cryptoConfig.createParameterSpec(encryptedPacket.iv);
			if (spec == null) {
				cipher.init(Cipher.DECRYPT_MODE, cryptoConfig.encryptionKey());
			} else {
				cipher.init(Cipher.DECRYPT_MODE, cryptoConfig.encryptionKey(), spec);
			}
			byte[] decryptedData = cipher.doFinal(encryptedPacket.ciphertext);

			System.out.print(".");
			System.out.flush();
			for (SocketAddress outSocketAddress : outSocketAddressSet)
			{
				outSocket.send(new DatagramPacket(decryptedData, decryptedData.length, outSocketAddress));
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

	private static class CryptoConfig {
		private static final String CONFIG_FILE = "Cryptoconfig.conf";
		private static final int DEFAULT_GCM_TAG_BITS = 128;

		final String name;
		final String ciphersuite;
		final byte[] key;
		final String hmac;
		final byte[] macKey;
		final String keyAlgorithm;
		final String mode;
		final int ivSizeBytes;
		final int gcmTagBits;

		private CryptoConfig(String name, String ciphersuite, byte[] key, String hmac, byte[] macKey) throws GeneralSecurityException {
			this.name = name;
			this.ciphersuite = ciphersuite;
			this.key = key;
			this.hmac = hmac;
			this.macKey = macKey;

			String[] parts = ciphersuite.split("/");
			String keyAlgorithm = parts[0];
			if ("CHACHA20-POLY1305".equalsIgnoreCase(ciphersuite)) {
				keyAlgorithm = "ChaCha20";
			}
			this.keyAlgorithm = keyAlgorithm;
			this.mode = parts.length > 1 ? parts[1] : "";
			this.gcmTagBits = DEFAULT_GCM_TAG_BITS;
			this.ivSizeBytes = determineIvSizeBytes();
		}

		static Map<String, CryptoConfig> loadAll() throws IOException, GeneralSecurityException {
			Map<String, Map<String, String>> sections = parseSections();
			Map<String, CryptoConfig> configs = new LinkedHashMap<>();

			for (Map.Entry<String, Map<String, String>> section : sections.entrySet()) {
				String name = section.getKey();
				Map<String, String> values = section.getValue();
				String ciphersuite = values.get("ciphersuite");
				String key = values.get("key");
				String hmac = values.get("hmac");
				String macKey = values.get("mackey");

				if (ciphersuite == null || key == null) {
					throw new IllegalArgumentException("Section " + name + " must define ciphersuite and key");
				}
				if ((hmac == null) != (macKey == null)) {
					throw new IllegalArgumentException("Section " + name + " must define both hmac and mackey, or neither");
				}

				configs.put(name, new CryptoConfig(name, ciphersuite, decodeKey(key), hmac, macKey == null ? null : decodeKey(macKey)));
			}

			return configs;
		}

		AlgorithmParameterSpec createParameterSpec(byte[] iv) {
			if (iv.length == 0) {
				return null;
			}
			if ("GCM".equalsIgnoreCase(mode)) {
				return new GCMParameterSpec(gcmTagBits, iv);
			}
			return new IvParameterSpec(iv);
		}

		SecretKey encryptionKey() {
			return new SecretKeySpec(key, keyAlgorithm);
		}

		boolean hasMac() {
			return hmac != null;
		}

		byte[] mac(byte[] data) throws GeneralSecurityException {
			Mac mac = Mac.getInstance(hmac);
			mac.init(new SecretKeySpec(macKey, hmac));
			return mac.doFinal(data);
		}

		int macLength() throws GeneralSecurityException {
			if (!hasMac()) {
				return 0;
			}
			Mac mac = Mac.getInstance(hmac);
			return mac.getMacLength();
		}

		int minimumCiphertextBytes() {
			if ("GCM".equalsIgnoreCase(mode) || "CHACHA20-POLY1305".equalsIgnoreCase(ciphersuite)) {
				return gcmTagBits / 8;
			}
			return 1;
		}

		private int determineIvSizeBytes() throws GeneralSecurityException {
			if ("ECB".equalsIgnoreCase(mode)) {
				return 0;
			}
			if ("GCM".equalsIgnoreCase(mode) || "CHACHA20-POLY1305".equalsIgnoreCase(ciphersuite)) {
				return 12;
			}

			Cipher cipher = Cipher.getInstance(ciphersuite);
			int blockSize = cipher.getBlockSize();
			if (blockSize <= 0) {
				throw new IllegalArgumentException("Cannot determine IV size for " + ciphersuite);
			}
			return blockSize;
		}

		private static Map<String, Map<String, String>> parseSections() throws IOException {
			Map<String, Map<String, String>> sections = new LinkedHashMap<>();
			BufferedReader reader = new BufferedReader(new FileReader(CONFIG_FILE));
			String currentSection = null;
			String line;

			while ((line = reader.readLine()) != null) {
				line = stripComment(line).trim();
				if (line.length() == 0) {
					continue;
				}
				if (line.startsWith("</") && line.endsWith(">")) {
					currentSection = null;
					continue;
				}
				if (line.startsWith("<") && line.endsWith(">")) {
					currentSection = line.substring(1, line.length() - 1).trim();
					sections.put(currentSection, new LinkedHashMap<String, String>());
					continue;
				}
				if (currentSection == null) {
					throw new IllegalArgumentException("Config entry outside a section: " + line);
				}

				int separator = line.indexOf(':');
				if (separator < 0) {
					throw new IllegalArgumentException("Invalid config entry: " + line);
				}
				String key = line.substring(0, separator).trim().toLowerCase();
				String value = line.substring(separator + 1).trim();
				sections.get(currentSection).put(key, value);
			}
			reader.close();
			return sections;
		}

		private static String stripComment(String line) {
			int comment = line.indexOf("//");
			return comment >= 0 ? line.substring(0, comment) : line;
		}

		private static byte[] decodeKey(String value) {
			value = value.trim();
			if (value.startsWith("<") && value.endsWith(">")) {
				value = value.substring(1, value.length() - 1).trim();
			}
			if (value.matches("(?i)[0-9a-f]+") && value.length() % 2 == 0) {
				byte[] bytes = new byte[value.length() / 2];
				for (int i = 0; i < bytes.length; i++) {
					bytes[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
				}
				return bytes;
			}
			try {
				return Base64.getDecoder().decode(value);
			} catch (IllegalArgumentException ignored) {
				return value.getBytes(StandardCharsets.UTF_8);
			}
		}
	}

	private static class EncryptedPacket {
		final CryptoConfig cryptoConfig;
		final byte[] authenticatedData;
		final byte[] iv;
		final byte[] ciphertext;
		final byte[] mac;

		private EncryptedPacket(CryptoConfig cryptoConfig, byte[] authenticatedData, byte[] iv, byte[] ciphertext, byte[] mac) {
			this.cryptoConfig = cryptoConfig;
			this.authenticatedData = authenticatedData;
			this.iv = iv;
			this.ciphertext = ciphertext;
			this.mac = mac;
		}

		static EncryptedPacket parse(byte[] packetData, Map<String, CryptoConfig> cryptoConfigs) throws GeneralSecurityException {
			if (packetData.length < 1) {
				return null;
			}
			int nameLength = packetData[0] & 0xff;
			if (packetData.length < 1 + nameLength) {
				return null;
			}
			String configName = new String(packetData, 1, nameLength, StandardCharsets.UTF_8);
			CryptoConfig cryptoConfig = cryptoConfigs.get(configName);
			if (cryptoConfig == null) {
				return null;
			}

			int offset = 1 + nameLength;
			int macLength = cryptoConfig.macLength();
			int minimumLength = offset + cryptoConfig.ivSizeBytes + cryptoConfig.minimumCiphertextBytes() + macLength;
			if (packetData.length < minimumLength) {
				return null;
			}

			byte[] authenticatedData = Arrays.copyOf(packetData, packetData.length - macLength);
			byte[] mac = Arrays.copyOfRange(packetData, packetData.length - macLength, packetData.length);
			byte[] iv = Arrays.copyOfRange(packetData, offset, offset + cryptoConfig.ivSizeBytes);
			byte[] ciphertext = Arrays.copyOfRange(packetData, offset + cryptoConfig.ivSizeBytes, packetData.length - macLength);
			return new EncryptedPacket(cryptoConfig, authenticatedData, iv, ciphertext, mac);
		}

		boolean hasValidMac() throws GeneralSecurityException {
			if (!cryptoConfig.hasMac()) {
				return true;
			}
			return MessageDigest.isEqual(cryptoConfig.mac(authenticatedData), mac);
		}
	}

}
