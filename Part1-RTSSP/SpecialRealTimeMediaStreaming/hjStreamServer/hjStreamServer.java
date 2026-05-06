/*
* hjStreamServer.java 
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
*/

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;


class hjStreamServer {

	static public void main( String []args ) throws Exception {
	        if (args.length != 3)
	        {
                   System.out.println("Erro, usar: mySend <movie> <ip-multicast-address> <port>");
	           System.out.println("        or: mySend <movie> <ip-unicast-address> <port>");
	           System.exit(-1);
                }

		int size;
		int csize = 0;
		int count = 0;
		int segmentsSent = 0;
		int sendFailures = 0;
		long encryptedBytes = 0;
 		long time;
		DataInputStream g = new DataInputStream( new FileInputStream(args[0]) );
		byte[] buff = new byte[4096];

		DatagramSocket s = new DatagramSocket();
		InetSocketAddress addr = new InetSocketAddress( args[1], Integer.parseInt(args[2]));
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
		long t0 = System.nanoTime(); // Ref. time 
		long q0 = 0;


	        // Movies are encoded in .dat files, where each
          	// frame is encoded in a real-time sequence of MP4 frames 
         	// Somewhat an FFMPEG4 playing scheme .. Dont worry
		
		// Each frame has:
		// Short size || Long Timestamp || byte[] EncodedMP4Frame
		// You can read (frame by frame to transmit ...
		// But you must folow the "real-time" encoding conditions

		// OK let's do it !

		Map<String, CryptoConfig> cryptoConfigs = CryptoConfig.loadAll();
		String cryptoConfigName = new File(args[0]).getName() + ".encrypted";
		CryptoConfig cryptoConfig = cryptoConfigs.get(cryptoConfigName);
		if (cryptoConfig == null) {
			throw new IllegalArgumentException("No crypto config section found for " + cryptoConfigName);
		}
		Key randomKey = cryptoConfig.encryptionKey();
		while ( g.available() > 0 ) {
		    
		    size = g.readShort(); // size of the frame
		    csize=csize+size;
		    time = g.readLong();  // timestamp of the frame
			if ( count == 0 ) q0 = time; // ref. time in the stream
			count += 1;
			g.readFully(buff, 0, size );
			p.setData(buff, 0, size );
			p.setSocketAddress( addr );

			// Encrypt only the current frame payload (size bytes).
			byte[] frameBytes = Arrays.copyOf(buff, size);
			byte[] iv = generateRandomIv(cryptoConfig);
			byte[] ciphertext = encrypt(frameBytes, randomKey, iv, cryptoConfig);
			byte[] packet = buildEncryptedPacket(cryptoConfig, iv, ciphertext);
			p.setData(packet, 0, packet.length);

			long t = System.nanoTime(); // what time is it?

			// Decision about the right time to transmit
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000));
		   
		        // send datagram (udp packet) w/ payload frame)
			// Frames sent in clear (no encryption)

			try {
				s.send(p);
				segmentsSent += 1;
				encryptedBytes += packet.length;
			} catch (IOException e) {
				sendFailures += 1;
			}

	           	// Just for awareness ... (debug)

			System.out.print( ":" );
		}

		long tend = System.nanoTime(); // "The end" time 
                System.out.println();
		System.out.println("DONE! all frames sent: "+ count);

		long duration=(tend-t0)/1000000000;
		System.out.println("Movie duration "+ duration + " s");
		System.out.println("Throughput "+ count/duration + " fps");
     	        System.out.println("Throughput "+ (8*(csize)/duration)/1000 + " Kbps");
		writeServerStats("hjStreamServer.stats.log", args[0], addr.toString(), cryptoConfig.name,
				cryptoConfig.ciphersuite, count, segmentsSent, sendFailures, csize, encryptedBytes, t0, tend);

	}

	private static void writeServerStats(String logFile, String movie, String destination, String configName,
										 String ciphersuite, int segmentsRead, int segmentsSent, int sendFailures,
										 long plaintextBytes, long encryptedBytes, long startNanos, long endNanos)
			throws IOException {
		double durationSeconds = Math.max(0.001, (endNanos - startNanos) / 1000000000.0);
		double attempted = segmentsRead;
		double failRate = attempted == 0 ? 0.0 : (sendFailures * 100.0) / attempted;
		PrintWriter out = new PrintWriter(new FileWriter(logFile, true));
		out.println("=== RTSSP Stream Server Stats " + LocalDateTime.now() + " ===");
		out.println("movie=" + movie);
		out.println("destination=" + destination);
		out.println("crypto_config=" + configName);
		out.println("ciphersuite=" + ciphersuite);
		out.println("segments_read=" + segmentsRead);
		out.println("segments_sent=" + segmentsSent);
		out.println("send_failures=" + sendFailures);
		out.printf("fail_rate_percent=%.2f%n", failRate);
		out.println("plaintext_bytes=" + plaintextBytes);
		out.println("encrypted_udp_bytes=" + encryptedBytes);
		out.printf("duration_seconds=%.3f%n", durationSeconds);
		out.printf("segments_per_second=%.2f%n", segmentsSent / durationSeconds);
		out.printf("payload_kbps=%.2f%n", (plaintextBytes * 8.0 / durationSeconds) / 1000.0);
		out.printf("encrypted_kbps=%.2f%n", (encryptedBytes * 8.0 / durationSeconds) / 1000.0);
		out.println();
		out.close();
	}

	private static byte[] encrypt(byte[] plaintext, Key key, byte[] iv, CryptoConfig cryptoConfig) throws Exception {
	    Cipher cipher = Cipher.getInstance(cryptoConfig.ciphersuite);
	    AlgorithmParameterSpec spec = cryptoConfig.createParameterSpec(iv);
	    if (spec == null) {
	        cipher.init(Cipher.ENCRYPT_MODE, key);
	    } else {
	        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
	    }
	    return cipher.doFinal(plaintext);
	}

	private static byte[] generateRandomIv(CryptoConfig cryptoConfig) {
	    byte[] iv = new byte[cryptoConfig.ivSizeBytes];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	}

	private static byte[] buildEncryptedPacket(CryptoConfig cryptoConfig, byte[] iv, byte[] ciphertext) throws GeneralSecurityException, IOException {
		byte[] configNameBytes = cryptoConfig.name.getBytes(StandardCharsets.UTF_8);
		if (configNameBytes.length > 255) {
			throw new IllegalArgumentException("Crypto config section name is too long");
		}

		ByteArrayOutputStream packet = new ByteArrayOutputStream();
		packet.write(configNameBytes.length);
		packet.write(configNameBytes);
		packet.write(iv);
		packet.write(ciphertext);

		if (cryptoConfig.hasMac()) {
			packet.write(cryptoConfig.mac(packet.toByteArray()));
		}
		return packet.toByteArray();
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



}
