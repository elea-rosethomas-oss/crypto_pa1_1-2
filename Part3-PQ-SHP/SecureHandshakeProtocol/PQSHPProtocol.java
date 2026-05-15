import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * PQ-SHP (Post-Quantum Secure Handshake Protocol) - Version 2
 * 
 * This is an extended version of SHP that uses post-quantum cryptographic algorithms
 * for resistance against quantum computing threats.
 * 
 * Key Changes from SHP v1:
 * - Digital Signatures: Crystals-Dilithium (ML-DSA-65) instead of ECDSA
 * - Key Agreement: Crystals-Kyber (ML-KEM-768) instead of ECDH
 * - Symmetric Encryption: Unchanged (AES-GCM, ChaCha20-Poly1305 are quantum-safe)
 * - Protocol Version: Changed to 2
 * 
 * NIST Standardization:
 * - FIPS 204: Dilithium (published August 2024)
 * - FIPS 203: Kyber (published August 2024)
 * 
 * This implementation provides a reference implementation and can use:
 * 1. liboqs-java library for production use (JNI bindings to liboqs C library)
 * 2. Bouncy Castle PQC provider (Dilithium support in v1.70+)
 * 3. Mock implementations for testing without external dependencies
 */
final class PQSHPProtocol {
	// Protocol constants
	static final int VERSION = 2;  // PQ-SHP Version
	static final int CLIENT_HELLO = 1;
	static final int SERVER_HELLO = 2;
	static final int CSSP = 3;
	static final int NONCE_BYTES = 32;
	
	// Post-Quantum Algorithm Constants (NIST FIPS 204/203)
	static final String PQ_SIGNATURE_ALGORITHM = "PQ-DILITHIUM";  // ML-DSA-65
	static final String PQ_KEM_ALGORITHM = "PQ-KYBER";           // ML-KEM-768
	
	// Dilithium (ML-DSA-65) Key Sizes
	static final int DILITHIUM_PUBLICKEY_BYTES = 1312;
	static final int DILITHIUM_PRIVATEKEY_BYTES = 2560;
	static final int DILITHIUM_SIGNATURE_BYTES = 2420;
	
	// Kyber (ML-KEM-768) Key Sizes
	static final int KYBER_PUBLICKEY_BYTES = 1184;
	static final int KYBER_SECRETKEY_BYTES = 2400;
	static final int KYBER_CIPHERTEXT_BYTES = 1088;
	static final int KYBER_SHAREDSECRET_BYTES = 32;
	
	// RTSSP Cipher suites (unchanged from SHP v1)
	static final String[] DEFAULT_CIPHERSUITES = new String[] {
		"AES/GCM/NoPadding",
		"CHACHA20-Poly1305",
		"AES/CTR/NoPadding"
	};

	private static final SecureRandom RANDOM = new SecureRandom();
	
	// Post-Quantum Cryptography Provider (simulated for reference implementation)
	// In production, replace with actual liboqs-java or Bouncy Castle integration
	private static final PQCryptoProvider PQ_PROVIDER = new PQCryptoProvider();

	private PQSHPProtocol() {
	}

	// ============================================================================
	// Key Generation
	// ============================================================================

	/**
	 * Generate a Dilithium key pair for entity authentication.
	 * Returns a wrapper containing both Dilithium public and private keys.
	 */
	static KeyPair generateDilithiumKeyPair() throws GeneralSecurityException {
		return PQ_PROVIDER.generateDilithiumKeyPair();
	}

	/**
	 * Generate a Kyber key pair for ephemeral key agreement.
	 * Returns a wrapper containing both Kyber public and private keys.
	 */
	static KeyPair generateKyberKeyPair() throws GeneralSecurityException {
		return PQ_PROVIDER.generateKyberKeyPair();
	}

	static byte[] randomNonce() {
		byte[] nonce = new byte[NONCE_BYTES];
		RANDOM.nextBytes(nonce);
		return nonce;
	}

	// ============================================================================
	// Challenge-Response
	// ============================================================================

	static byte[] challengeResponse(byte[] nonce) throws GeneralSecurityException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update("PQ-SHP challenge response".getBytes(StandardCharsets.UTF_8));
		digest.update(nonce);
		return digest.digest();
	}

	// ============================================================================
	// Certificate Management
	// ============================================================================

	/**
	 * Create a self-signed PQ certificate for entity identity.
	 * Uses Dilithium for signing.
	 */
	static PQCertificate createPQCertificate(String subject, KeyPair identity) 
			throws GeneralSecurityException, IOException {
		byte[] publicKey = identity.getPublic().getEncoded();
		byte[] signed = certificateSignedBytes(subject, publicKey);
		byte[] signature = signWithDilithium(identity.getPrivate(), signed);
		return new PQCertificate(subject, publicKey, signature);
	}

	// ============================================================================
	// Client Hello Message
	// ============================================================================

	static ClientHello createClientHello(String movie, PQCertificate certificate, 
										KeyPair kyberKeyPair, String[] ciphersuites, 
										byte[] nonce, PrivateKey signingKey)
			throws GeneralSecurityException, IOException {
		ClientHello hello = new ClientHello(movie, certificate, kyberKeyPair.getPublic().getEncoded(), 
											ciphersuites, nonce, null, null);
		byte[] signedBytes = encodeClientHelloUnsigned(hello);
		byte[] signature = signWithDilithium(signingKey, signedBytes);
		byte[] encoded = encodeClientHelloUnsigned(new ClientHello(movie, certificate, 
											kyberKeyPair.getPublic().getEncoded(), 
											ciphersuites, nonce, signature, null));
		return new ClientHello(movie, certificate, kyberKeyPair.getPublic().getEncoded(), 
							  ciphersuites, nonce, signature, encoded);
	}

	static byte[] encodeClientHello(ClientHello hello) throws IOException {
		return encodeClientHelloUnsigned(hello);
	}

	static ClientHello parseClientHello(byte[] bytes) throws Exception {
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
		int type = in.readUnsignedByte();
		int version = in.readUnsignedByte();
		if (type != CLIENT_HELLO || version != VERSION) {
			throw new IOException("Invalid PQ-SHP ClientHello");
		}
		String movie = readString(in);
		PQCertificate certificate = readPQCertificate(in);
		byte[] kyberPublicKey = readBytes(in);
		String[] ciphersuites = readStringList(in);
		byte[] nonce = readBytes(in);
		byte[] signature = readBytes(in);
		ClientHello hello = new ClientHello(movie, certificate, kyberPublicKey, ciphersuites, nonce, signature, bytes);
		
		// Verify certificate and signature
		if (!certificate.isValid() || !verifyWithDilithium(certificate.publicKey(), 
													encodeClientHelloUnsigned(unsigned(hello)), signature)) {
			throw new GeneralSecurityException("Invalid PQ-SHP ClientHello signature");
		}
		return hello;
	}

	// ============================================================================
	// Server Hello Message
	// ============================================================================

	static ServerHello createServerHello(String movie, boolean clientCertificateOk, 
										PQCertificate certificate, KeyPair kyberKeyPair, 
										String ciphersuite, byte[] nonce, 
										byte[] clientChallengeResponse, PrivateKey signingKey)
			throws GeneralSecurityException, IOException {
		ServerHello hello = new ServerHello(movie, clientCertificateOk, certificate, 
											kyberKeyPair.getPublic().getEncoded(), 
											ciphersuite, nonce, clientChallengeResponse, null, null);
		byte[] signedBytes = encodeServerHelloUnsigned(hello);
		byte[] signature = signWithDilithium(signingKey, signedBytes);
		byte[] encoded = encodeServerHelloUnsigned(new ServerHello(movie, clientCertificateOk, 
											certificate, kyberKeyPair.getPublic().getEncoded(),
											ciphersuite, nonce, clientChallengeResponse, signature, null));
		return new ServerHello(movie, clientCertificateOk, certificate, 
							  kyberKeyPair.getPublic().getEncoded(), ciphersuite, 
							  nonce, clientChallengeResponse, signature, encoded);
	}

	static byte[] encodeServerHello(ServerHello hello) throws IOException {
		return encodeServerHelloUnsigned(hello);
	}

	static ServerHello parseServerHello(byte[] bytes) throws Exception {
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
		int type = in.readUnsignedByte();
		int version = in.readUnsignedByte();
		if (type != SERVER_HELLO || version != VERSION) {
			throw new IOException("Invalid PQ-SHP ServerHello");
		}
		String movie = readString(in);
		boolean clientCertificateOk = in.readBoolean();
		PQCertificate certificate = readPQCertificate(in);
		byte[] kyberPublicKey = readBytes(in);
		String ciphersuite = readString(in);
		byte[] nonce = readBytes(in);
		byte[] clientChallengeResponse = readBytes(in);
		byte[] signature = readBytes(in);
		ServerHello hello = new ServerHello(movie, clientCertificateOk, certificate, 
											kyberPublicKey, ciphersuite, nonce, 
											clientChallengeResponse, signature, bytes);
		
		// Verify certificate and signature
		if (!certificate.isValid() || !verifyWithDilithium(certificate.publicKey(), 
													encodeServerHelloUnsigned(unsigned(hello)), signature)) {
			throw new GeneralSecurityException("Invalid PQ-SHP ServerHello signature");
		}
		return hello;
	}

	// ============================================================================
	// CSSP (Crypto Stream Session Protocol) - Unchanged
	// ============================================================================

	static CsspPlaintext createCsspPlaintext(String movie, byte[] serverNonce) throws GeneralSecurityException {
		return new CsspPlaintext(movie, challengeResponse(serverNonce), "START_RTSSP");
	}

	static byte[] encodeCssp(CsspPlaintext plaintext, SessionKeys keys) throws Exception {
		byte[] iv = new byte[keys.ivSizeBytes];
		RANDOM.nextBytes(iv);
		byte[] plaintextBytes = encodeCsspPlaintext(plaintext);
		Cipher cipher = Cipher.getInstance(keys.ciphersuite);
		if (keys.usesGcm()) {
			cipher.init(Cipher.ENCRYPT_MODE, keys.encryptionKey(), new GCMParameterSpec(128, iv));
		} else if (keys.ivSizeBytes == 0) {
			cipher.init(Cipher.ENCRYPT_MODE, keys.encryptionKey());
		} else {
			cipher.init(Cipher.ENCRYPT_MODE, keys.encryptionKey(), new IvParameterSpec(iv));
		}
		byte[] ciphertext = cipher.doFinal(plaintextBytes);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream data = new DataOutputStream(out);
		data.writeByte(CSSP);
		data.writeByte(VERSION);
		writeString(data, keys.ciphersuite);
		writeBytes(data, iv);
		writeBytes(data, ciphertext);
		byte[] authenticated = out.toByteArray();
		writeBytes(data, keys.hmacAlgorithm == null ? new byte[0] : keys.mac(authenticated));
		data.flush();
		return out.toByteArray();
	}

	static CsspPlaintext parseCssp(byte[] bytes, SessionKeys keys) throws Exception {
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
		int type = in.readUnsignedByte();
		int version = in.readUnsignedByte();
		if (type != CSSP || version != VERSION) {
			throw new IOException("Invalid PQ-SHP CSSP");
		}
		String ciphersuite = readString(in);
		if (!keys.ciphersuite.equals(ciphersuite)) {
			throw new GeneralSecurityException("CSSP ciphersuite mismatch");
		}
		byte[] iv = readBytes(in);
		byte[] ciphertext = readBytes(in);
		byte[] receivedMac = readBytes(in);
		int authenticatedLength = bytes.length - 2 - receivedMac.length;
		byte[] authenticated = Arrays.copyOf(bytes, authenticatedLength);
		if (keys.hmacAlgorithm != null && !MessageDigest.isEqual(keys.mac(authenticated), receivedMac)) {
			throw new GeneralSecurityException("Invalid CSSP MAC");
		}

		Cipher cipher = Cipher.getInstance(keys.ciphersuite);
		if (keys.usesGcm()) {
			cipher.init(Cipher.DECRYPT_MODE, keys.encryptionKey(), new GCMParameterSpec(128, iv));
		} else if (keys.ivSizeBytes == 0) {
			cipher.init(Cipher.DECRYPT_MODE, keys.encryptionKey());
		} else {
			cipher.init(Cipher.DECRYPT_MODE, keys.encryptionKey(), new IvParameterSpec(iv));
		}
		return parseCsspPlaintext(cipher.doFinal(ciphertext));
	}

	// ============================================================================
	// Session Key Derivation (Post-Quantum)
	// ============================================================================

	/**
	 * Derive session keys from post-quantum key agreement.
	 * 
	 * 1. Decapsulate Kyber ciphertext or perform key derivation
	 * 2. Use HKDF-SHA256 with:
	 *    - Input Key Material (IKM): Kyber shared secret
	 *    - Salt: Hash(clientNonce || serverNonce)
	 *    - Info: "PQ-SHP RTSSP key schedule " || ciphersuite || transcriptHash
	 * 3. Output: 64 bytes (32-byte encryption key + 32-byte MAC key)
	 */
	static SessionKeys deriveSessionKeys(PrivateKey kyberPrivateKey, byte[] kyberCiphertextOrPublicKey, 
										String ciphersuite, byte[] clientNonce, byte[] serverNonce, 
										byte[] clientHello, byte[] serverHello)
			throws Exception {
		
		// Derive the shared secret using Kyber
		byte[] sharedSecret = PQ_PROVIDER.kyberDecapsulate(kyberPrivateKey, kyberCiphertextOrPublicKey);
		
		// KDF salt = Hash(clientNonce || serverNonce)
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(clientNonce);
		digest.update(serverNonce);
		byte[] salt = digest.digest();

		// Compute transcript hash for binding to handshake
		digest.reset();
		digest.update(clientHello);
		digest.update(serverHello);
		byte[] transcriptHash = digest.digest();

		// HKDF-SHA256
		byte[] prk = hkdfExtract(salt, sharedSecret);
		byte[] keyBlock = hkdfExpand(prk, concat(
			"PQ-SHP RTSSP key schedule ".getBytes(StandardCharsets.UTF_8),
			ciphersuite.getBytes(StandardCharsets.UTF_8), 
			transcriptHash), 64);

		String hmac = requiresExternalMac(ciphersuite) ? "HmacSHA256" : null;
		return new SessionKeys(ciphersuite, Arrays.copyOfRange(keyBlock, 0, 32),
				hmac == null ? null : Arrays.copyOfRange(keyBlock, 32, 64), hmac);
	}

	// ============================================================================
	// Ciphersuite Negotiation
	// ============================================================================

	static String chooseCiphersuite(String[] offered) {
		List<String> serverPreference = Arrays.asList(DEFAULT_CIPHERSUITES);
		for (String preferred : serverPreference) {
			for (String candidate : offered) {
				if (preferred.equalsIgnoreCase(candidate)) {
					return preferred;
				}
			}
		}
		return null;
	}

	// ============================================================================
	// Digital Signature Operations (Dilithium-based)
	// ============================================================================

	static byte[] signWithDilithium(PrivateKey privateKey, byte[] message) throws GeneralSecurityException {
		return PQ_PROVIDER.dilithiumSign(privateKey, message);
	}

	static boolean verifyWithDilithium(PublicKey publicKey, byte[] message, byte[] signature) 
			throws GeneralSecurityException {
		return PQ_PROVIDER.dilithiumVerify(publicKey, message, signature);
	}

	// ============================================================================
	// Key Encapsulation (Kyber-based)
	// ============================================================================

	/**
	 * Encapsulate using Kyber: generates a shared secret and ciphertext.
	 * Used by server to create a secret that only the client (who has the private key) can decapsulate.
	 */
	static byte[] kyberEncapsulate(PublicKey kyberPublicKey) throws GeneralSecurityException {
		return PQ_PROVIDER.kyberEncapsulate(kyberPublicKey);
	}

	/**
	 * Decapsulate using Kyber: recovers the shared secret from ciphertext using private key.
	 */
	static byte[] kyberDecapsulate(PrivateKey kyberPrivateKey, byte[] ciphertext) 
			throws GeneralSecurityException {
		return PQ_PROVIDER.kyberDecapsulate(kyberPrivateKey, ciphertext);
	}

	// ============================================================================
	// Private: Message Encoding/Decoding
	// ============================================================================

	private static ClientHello unsigned(ClientHello hello) {
		return new ClientHello(hello.movie, hello.certificate, hello.kyberPublicKey, 
							   hello.ciphersuites, hello.nonce, null, hello.encoded);
	}

	private static ServerHello unsigned(ServerHello hello) {
		return new ServerHello(hello.movie, hello.clientCertificateOk, hello.certificate, 
							   hello.kyberPublicKey, hello.ciphersuite, hello.nonce, 
							   hello.clientChallengeResponse, null, hello.encoded);
	}

	private static byte[] encodeClientHelloUnsigned(ClientHello hello) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream data = new DataOutputStream(out);
		data.writeByte(CLIENT_HELLO);
		data.writeByte(VERSION);
		writeString(data, hello.movie);
		writePQCertificate(data, hello.certificate);
		writeBytes(data, hello.kyberPublicKey);
		writeStringList(data, hello.ciphersuites);
		writeBytes(data, hello.nonce);
		if (hello.signature != null) {
			writeBytes(data, hello.signature);
		}
		data.flush();
		return out.toByteArray();
	}

	private static byte[] encodeServerHelloUnsigned(ServerHello hello) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream data = new DataOutputStream(out);
		data.writeByte(SERVER_HELLO);
		data.writeByte(VERSION);
		writeString(data, hello.movie);
		data.writeBoolean(hello.clientCertificateOk);
		writePQCertificate(data, hello.certificate);
		writeBytes(data, hello.kyberPublicKey);
		writeString(data, hello.ciphersuite);
		writeBytes(data, hello.nonce);
		writeBytes(data, hello.clientChallengeResponse);
		if (hello.signature != null) {
			writeBytes(data, hello.signature);
		}
		data.flush();
		return out.toByteArray();
	}

	private static byte[] encodeCsspPlaintext(CsspPlaintext plaintext) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream data = new DataOutputStream(out);
		writeString(data, plaintext.movie);
		writeBytes(data, plaintext.serverChallengeResponse);
		writeString(data, plaintext.command);
		data.flush();
		return out.toByteArray();
	}

	private static CsspPlaintext parseCsspPlaintext(byte[] bytes) throws IOException {
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
		return new CsspPlaintext(readString(in), readBytes(in), readString(in));
	}

	private static void writePQCertificate(DataOutputStream out, PQCertificate certificate) throws IOException {
		writeString(out, certificate.subject);
		writeBytes(out, certificate.publicKey);
		writeBytes(out, certificate.signature);
	}

	private static PQCertificate readPQCertificate(DataInputStream in) throws IOException {
		return new PQCertificate(readString(in), readBytes(in), readBytes(in));
	}

	private static byte[] certificateSignedBytes(String subject, byte[] publicKey) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream data = new DataOutputStream(out);
		writeString(data, subject);
		writeBytes(data, publicKey);
		data.flush();
		return out.toByteArray();
	}

	private static void writeStringList(DataOutputStream out, String[] values) throws IOException {
		out.writeShort(values.length);
		for (String value : values) {
			writeString(out, value);
		}
	}

	private static String[] readStringList(DataInputStream in) throws IOException {
		int size = in.readUnsignedShort();
		List<String> values = new ArrayList<>();
		for (int i = 0; i < size; i++) {
			values.add(readString(in));
		}
		return values.toArray(new String[0]);
	}

	private static void writeString(DataOutputStream out, String value) throws IOException {
		writeBytes(out, value.getBytes(StandardCharsets.UTF_8));
	}

	private static String readString(DataInputStream in) throws IOException {
		return new String(readBytes(in), StandardCharsets.UTF_8);
	}

	private static void writeBytes(DataOutputStream out, byte[] bytes) throws IOException {
		out.writeShort(bytes.length);
		out.write(bytes);
	}

	private static byte[] readBytes(DataInputStream in) throws IOException {
		int length = in.readUnsignedShort();
		byte[] bytes = new byte[length];
		in.readFully(bytes);
		return bytes;
	}

	// ============================================================================
	// HKDF-SHA256 (Unchanged from SHP v1)
	// ============================================================================

	private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(salt, "HmacSHA256"));
		return mac.doFinal(ikm);
	}

	private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(prk, "HmacSHA256"));
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		byte[] previous = new byte[0];
		byte counter = 1;
		while (out.size() < length) {
			mac.reset();
			mac.update(previous);
			mac.update(info);
			mac.update(counter);
			previous = mac.doFinal();
			out.write(previous, 0, previous.length);
			counter++;
		}
		return Arrays.copyOf(out.toByteArray(), length);
	}

	private static byte[] concat(byte[]... parts) {
		int length = 0;
		for (byte[] part : parts) {
			length += part.length;
		}
		byte[] result = new byte[length];
		int offset = 0;
		for (byte[] part : parts) {
			System.arraycopy(part, 0, result, offset, part.length);
			offset += part.length;
		}
		return result;
	}

	static boolean requiresExternalMac(String ciphersuite) {
		return ciphersuite.toUpperCase().contains("/CTR/");
	}

	// ============================================================================
	// Inner Classes: Message Types
	// ============================================================================

	static final class PQCertificate {
		final String subject;
		final byte[] publicKey;     // Dilithium public key (1,312 bytes)
		final byte[] signature;     // Dilithium signature (2,420 bytes)

		PQCertificate(String subject, byte[] publicKey, byte[] signature) {
			this.subject = subject;
			this.publicKey = publicKey;
			this.signature = signature;
		}

		PublicKey publicKey() throws GeneralSecurityException {
			return PQ_PROVIDER.decodeDilithiumPublicKey(publicKey);
		}

		boolean isValid() throws GeneralSecurityException, IOException {
			return verifyWithDilithium(publicKey(), certificateSignedBytes(subject, publicKey), signature);
		}
	}

	static final class ClientHello {
		final String movie;
		final PQCertificate certificate;
		final byte[] kyberPublicKey;      // Kyber public key (1,184 bytes)
		final String[] ciphersuites;
		final byte[] nonce;
		final byte[] signature;           // Dilithium signature
		final byte[] encoded;

		ClientHello(String movie, PQCertificate certificate, byte[] kyberPublicKey, 
					String[] ciphersuites, byte[] nonce, byte[] signature, byte[] encoded) {
			this.movie = movie;
			this.certificate = certificate;
			this.kyberPublicKey = kyberPublicKey;
			this.ciphersuites = ciphersuites;
			this.nonce = nonce;
			this.signature = signature;
			this.encoded = encoded;
		}
	}

	static final class ServerHello {
		final String movie;
		final boolean clientCertificateOk;
		final PQCertificate certificate;
		final byte[] kyberPublicKey;      // Kyber public key (1,184 bytes)
		final String ciphersuite;
		final byte[] nonce;
		final byte[] clientChallengeResponse;
		final byte[] signature;           // Dilithium signature
		final byte[] encoded;

		ServerHello(String movie, boolean clientCertificateOk, PQCertificate certificate, 
					byte[] kyberPublicKey, String ciphersuite, byte[] nonce, 
					byte[] clientChallengeResponse, byte[] signature, byte[] encoded) {
			this.movie = movie;
			this.clientCertificateOk = clientCertificateOk;
			this.certificate = certificate;
			this.kyberPublicKey = kyberPublicKey;
			this.ciphersuite = ciphersuite;
			this.nonce = nonce;
			this.clientChallengeResponse = clientChallengeResponse;
			this.signature = signature;
			this.encoded = encoded;
		}
	}

	static final class CsspPlaintext {
		final String movie;
		final byte[] serverChallengeResponse;
		final String command;

		CsspPlaintext(String movie, byte[] serverChallengeResponse, String command) {
			this.movie = movie;
			this.serverChallengeResponse = serverChallengeResponse;
			this.command = command;
		}
	}

	static final class SessionKeys {
		final String ciphersuite;
		final byte[] encryptionKey;
		final byte[] macKey;
		final String hmacAlgorithm;
		final int ivSizeBytes;
		final String keyAlgorithm;

		SessionKeys(String ciphersuite, byte[] encryptionKey, byte[] macKey, String hmacAlgorithm) {
			this.ciphersuite = ciphersuite;
			this.encryptionKey = encryptionKey;
			this.macKey = macKey;
			this.hmacAlgorithm = hmacAlgorithm;
			this.ivSizeBytes = determineIvSizeBytes(ciphersuite);
			this.keyAlgorithm = ciphersuite.equalsIgnoreCase("CHACHA20-Poly1305") ? "ChaCha20" : ciphersuite.split("/")[0];
		}

		SecretKeySpec encryptionKey() {
			return new SecretKeySpec(encryptionKey, keyAlgorithm);
		}

		byte[] mac(byte[] data) throws GeneralSecurityException {
			Mac mac = Mac.getInstance(hmacAlgorithm);
			mac.init(new SecretKeySpec(macKey, hmacAlgorithm));
			return mac.doFinal(data);
		}

		boolean usesGcm() {
			return ciphersuite.toUpperCase().contains("/GCM/");
		}

		private static int determineIvSizeBytes(String ciphersuite) {
			if (ciphersuite.toUpperCase().contains("/ECB/")) {
				return 0;
			}
			if (ciphersuite.toUpperCase().contains("/GCM/") || ciphersuite.equalsIgnoreCase("CHACHA20-Poly1305")) {
				return 12;
			}
			return 16;
		}
	}
}

