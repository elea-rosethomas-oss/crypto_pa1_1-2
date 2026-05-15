/*
 * hjUDPproxyPQSHP.java
 *
 * Post-Quantum Secure Handshake Protocol (PQ-SHP) UDP Proxy
 *
 * This proxy implements PQ-SHP handshake for post-quantum secure
 * media streaming in RTSSP protocol. It initiates the handshake with
 * the server using Crystals-Dilithium for signatures and Crystals-Kyber
 * for key establishment.
 *
 * Handshake Flow:
 * 1. Proxy generates PQ ClientHello (Kyber public key, certificate, nonce)
 * 2. Proxy sends ClientHello to server
 * 3. Proxy receives PQ ServerHello (Kyber ciphertext, certificate, signature)
 * 4. Proxy derives shared secret using Kyber
 * 5. Proxy sends encrypted CSSP with confirmation
 * 6. Proxy begins forwarding encrypted RTSSP packets from server to client
 */

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

class hjUDPproxyPQSHP {

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
		String pqShpServer = properties.getProperty("server", "localhost:9999");
		String movie = properties.getProperty("movie", "cars.dat");

		SocketAddress inSocketAddress = parseSocketAddress(remote);
		Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(","))
			.map(s -> parseSocketAddress(s))
			.collect(Collectors.toSet());

		DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
		DatagramSocket outSocket = new DatagramSocket();
		byte[] buffer = new byte[8 * 1024];

		System.out.println("=== PQ-SHP UDP Proxy ===");
		System.out.println("Initiating PQ-SHP handshake with server: " + pqShpServer);
		System.out.println("Using post-quantum cryptography: Dilithium + Kyber");

		long handshakeStart = System.nanoTime();
		PQSHPProtocol.SessionKeys sessionKeys = performPostQuantumSecureHandshake(pqShpServer, movie);
		long handshakeEnd = System.nanoTime();

		Map<String, CryptoConfig> cryptoConfigs = new LinkedHashMap<>();
		CryptoConfig sessionConfig = CryptoConfig.fromSession(movie + ".encrypted", sessionKeys);
		cryptoConfigs.put(sessionConfig.name, sessionConfig);
		System.out.println("PQ-SHP ready: " + sessionKeys.ciphersuite + " for " + movie);

		final ProxyStats stats = new ProxyStats(remote, destinations, pqShpServer, movie,
				sessionKeys.ciphersuite, handshakeStart, handshakeEnd);

		Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
			public void run() {
				try {
					writeProxyStats("hjUDPproxyPQSHP.stats.log", stats);
				} catch (IOException e) {
					System.err.println("Could not write PQ-SHP proxy stats: " + e.getMessage());
				}
			}
		}));

		System.out.println("\nForwarding encrypted RTSSP packets...");
		while (true) {
			DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
			inSocket.receive(inPacket);

			int len = inPacket.getLength();
			stats.receivedSegments += 1;
			stats.receivedBytes += len;
			byte[] packetData = Arrays.copyOf(inPacket.getData(), len);
			EncryptedPacket encryptedPacket = EncryptedPacket.parse(packetData, cryptoConfigs);
			if (encryptedPacket == null) {
				stats.parseDrops += 1;
				continue;
			}
			CryptoConfig cryptoConfig = encryptedPacket.cryptoConfig;
			if (!encryptedPacket.hasValidMac()) {
				stats.macDrops += 1;
				continue;
			}

			byte[] decryptedData;
			try {
				Cipher cipher = Cipher.getInstance(cryptoConfig.ciphersuite);
				AlgorithmParameterSpec spec = cryptoConfig.createParameterSpec(encryptedPacket.iv);
				if (spec == null) {
					cipher.init(Cipher.DECRYPT_MODE, cryptoConfig.encryptionKey());
				} else {
					cipher.init(Cipher.DECRYPT_MODE, cryptoConfig.encryptionKey(), spec);
				}
				decryptedData = cipher.doFinal(encryptedPacket.ciphertext);
			} catch (GeneralSecurityException e) {
				stats.decryptDrops += 1;
				continue;
			}
			stats.forwardableSegments += 1;
			stats.decryptedBytes += decryptedData.length;

			System.out.print(".");
			System.out.flush();
			for (SocketAddress outSocketAddress : outSocketAddressSet)
			{
				try {
					outSocket.send(new DatagramPacket(decryptedData, decryptedData.length, outSocketAddress));
					stats.deliveredDatagrams += 1;
					stats.deliveredBytes += decryptedData.length;
				} catch (IOException e) {
					stats.deliveryFailures += 1;
				}
			}
		}
	}

	private static void writeProxyStats(String logFile, ProxyStats stats) throws IOException {
		long endNanos = System.nanoTime();
		double durationSeconds = Math.max(0.001, (endNanos - stats.startNanos) / 1000000000.0);
		double handshakeSeconds = Math.max(0.0, (stats.handshakeEndNanos - stats.handshakeStartNanos) / 1000000000.0);
		long drops = stats.parseDrops + stats.macDrops + stats.decryptDrops;
		double failRate = stats.receivedSegments == 0 ? 0.0 : ((drops + stats.deliveryFailures) * 100.0) / stats.receivedSegments;
		PrintWriter out = new PrintWriter(new FileWriter(logFile, true));
		out.println("=== PQ-SHP UDP Proxy Stats " + LocalDateTime.now() + " ===");
		out.println("protocol=PQ-SHP-v2");
		out.println("movie=" + stats.movie);
		out.println("remote=" + stats.remote);
		out.println("localdelivery=" + stats.destinations);
		out.println("pq_shp_server=" + stats.pqShpServer);
		out.println("ciphersuite=" + stats.ciphersuite);
		out.printf("handshake_seconds=%.3f%n", handshakeSeconds);
		out.println("received_segments=" + stats.receivedSegments);
		out.println("forwardable_segments=" + stats.forwardableSegments);
		out.println("delivered_datagrams=" + stats.deliveredDatagrams);
		out.println("parse_drops=" + stats.parseDrops);
		out.println("mac_drops=" + stats.macDrops);
		out.println("decrypt_drops=" + stats.decryptDrops);
		out.println("delivery_failures=" + stats.deliveryFailures);
		out.printf("fail_rate_percent=%.2f%n", failRate);
		out.println("received_bytes=" + stats.receivedBytes);
		out.println("decrypted_bytes=" + stats.decryptedBytes);
		out.println("delivered_bytes=" + stats.deliveredBytes);
		out.printf("duration_seconds=%.3f%n", durationSeconds);
		out.printf("received_segments_per_second=%.2f%n", stats.receivedSegments / durationSeconds);
		out.printf("delivered_datagrams_per_second=%.2f%n", stats.deliveredDatagrams / durationSeconds);
		out.printf("received_kbps=%.2f%n", (stats.receivedBytes * 8.0 / durationSeconds) / 1000.0);
		out.printf("delivered_kbps=%.2f%n", (stats.deliveredBytes * 8.0 / durationSeconds) / 1000.0);
		out.println();
		out.close();
	}

	private static class ProxyStats {
		final String remote;
		final String destinations;
		final String pqShpServer;
		final String movie;
		final String ciphersuite;
		final long handshakeStartNanos;
		final long handshakeEndNanos;
		final long startNanos = System.nanoTime();
		long receivedSegments;
		long forwardableSegments;
		long deliveredDatagrams;
		long parseDrops;
		long macDrops;
		long decryptDrops;
		long deliveryFailures;
		long receivedBytes;
		long decryptedBytes;
		long deliveredBytes;

		ProxyStats(String remote, String destinations, String pqShpServer, String movie, String ciphersuite,
				   long handshakeStartNanos, long handshakeEndNanos) {
			this.remote = remote;
			this.destinations = destinations;
			this.pqShpServer = pqShpServer;
			this.movie = movie;
			this.ciphersuite = ciphersuite;
			this.handshakeStartNanos = handshakeStartNanos;
			this.handshakeEndNanos = handshakeEndNanos;
		}
	}

	private static InetSocketAddress parseSocketAddress(String socketAddress)
	{
		String[] split = socketAddress.split(":");
		String host = split[0];
		int port = Integer.parseInt(split[1]);
		return new InetSocketAddress(host, port);
	}

	private static PQSHPProtocol.SessionKeys performPostQuantumSecureHandshake(String serverEndpoint, String movie) throws Exception {
		InetSocketAddress serverAddress = parseSocketAddress(serverEndpoint);
		DatagramSocket socket = new DatagramSocket();
		socket.setSoTimeout(10000);

		// Generate Dilithium keys for authentication
		KeyPair dilithiumIdentity = PQSHPProtocol.generateDilithiumKeyPair();
		// Generate Kyber keys for key establishment
		KeyPair kyberEphemeralPair = PQSHPProtocol.generateKyberKeyPair();

		PQSHPProtocol.PQCertificate clientCert = PQSHPProtocol.createPQCertificate("proxy", dilithiumIdentity);
		byte[] clientNonce = PQSHPProtocol.randomNonce();

		// Create and send ClientHello
		PQSHPProtocol.ClientHello clientHello = PQSHPProtocol.createClientHello(movie, clientCert,
			kyberEphemeralPair, PQSHPProtocol.DEFAULT_CIPHERSUITES, clientNonce, dilithiumIdentity.getPrivate());
		byte[] clientHelloBytes = PQSHPProtocol.encodeClientHello(clientHello);
		System.out.println("Sending PQ-SHP ClientHello with " + clientHello.ciphersuites.length + " ciphersuites");
		socket.send(new DatagramPacket(clientHelloBytes, clientHelloBytes.length, serverAddress));

		// Receive ServerHello
		System.out.println("Waiting for PQ-SHP ServerHello...");
		byte[] buffer = new byte[8192];
		DatagramPacket response = new DatagramPacket(buffer, buffer.length);
		socket.receive(response);
		byte[] serverHelloBytes = Arrays.copyOf(response.getData(), response.getLength());
		PQSHPProtocol.ServerHello serverHello = PQSHPProtocol.parseServerHello(serverHelloBytes);
		System.out.println("Received PQ-SHP ServerHello with ciphersuite: " + serverHello.ciphersuite);

		if (!movie.equals(serverHello.movie)) {
			throw new GeneralSecurityException("PQ-SHP ServerHello confirmed a different movie");
		}
		if (!serverHello.clientCertificateOk) {
			throw new GeneralSecurityException("PQ-SHP server rejected the proxy certificate");
		}
		if (!MessageDigest.isEqual(PQSHPProtocol.challengeResponse(clientNonce), serverHello.clientChallengeResponse)) {
			throw new GeneralSecurityException("PQ-SHP server failed the client nonce challenge");
		}

		// Derive session keys using post-quantum key agreement
		PQSHPProtocol.SessionKeys sessionKeys = PQSHPProtocol.deriveSessionKeys(
			kyberEphemeralPair.getPrivate(), serverHello.kyberPublicKey,
			serverHello.ciphersuite, clientNonce, serverHello.nonce, clientHelloBytes, serverHelloBytes);

		// Create and send CSSP
		PQSHPProtocol.CsspPlaintext cssp = PQSHPProtocol.createCsspPlaintext(movie, serverHello.nonce);
		byte[] csspBytes = PQSHPProtocol.encodeCssp(cssp, sessionKeys);
		System.out.println("Sending encrypted CSSP confirmation");
		socket.send(new DatagramPacket(csspBytes, csspBytes.length, response.getSocketAddress()));
		socket.close();
		return sessionKeys;
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

		static CryptoConfig fromSession(String name, PQSHPProtocol.SessionKeys sessionKeys) throws GeneralSecurityException {
			return new CryptoConfig(name, sessionKeys.ciphersuite, sessionKeys.encryptionKey,
					sessionKeys.hmacAlgorithm, sessionKeys.macKey);
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

