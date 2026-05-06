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

final class SHPProtocol {
	static final int VERSION = 1;
	static final int CLIENT_HELLO = 1;
	static final int SERVER_HELLO = 2;
	static final int CSSP = 3;
	static final int NONCE_BYTES = 32;
	static final String CURVE = "secp256r1";
	static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
	static final String ECDH_ALGORITHM = "ECDH";
	static final String[] DEFAULT_CIPHERSUITES = new String[] {
		"AES/GCM/NoPadding",
		"CHACHA20-Poly1305",
		"AES/CTR/NoPadding"
	};

	private static final SecureRandom RANDOM = new SecureRandom();

	private SHPProtocol() {
	}

	static KeyPair generateEcKeyPair() throws GeneralSecurityException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		try {
			generator.initialize(new ECGenParameterSpec(CURVE), RANDOM);
		} catch (InvalidAlgorithmParameterException ignored) {
			generator.initialize(256, RANDOM);
		}
		return generator.generateKeyPair();
	}

	static byte[] randomNonce() {
		byte[] nonce = new byte[NONCE_BYTES];
		RANDOM.nextBytes(nonce);
		return nonce;
	}

	static byte[] challengeResponse(byte[] nonce) throws GeneralSecurityException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update("SHP challenge response".getBytes(StandardCharsets.UTF_8));
		digest.update(nonce);
		return digest.digest();
	}

	static Certificate createCertificate(String subject, KeyPair identity) throws GeneralSecurityException, IOException {
		byte[] publicKey = identity.getPublic().getEncoded();
		byte[] signed = certificateSignedBytes(subject, publicKey);
		byte[] signature = sign(identity.getPrivate(), signed);
		return new Certificate(subject, publicKey, signature);
	}

	static ClientHello createClientHello(String movie, Certificate certificate, KeyPair ecdhKeyPair,
										 String[] ciphersuites, byte[] nonce, PrivateKey signingKey)
			throws GeneralSecurityException, IOException {
		ClientHello hello = new ClientHello(movie, certificate, ecdhKeyPair.getPublic().getEncoded(), ciphersuites, nonce, null, null);
		byte[] signedBytes = encodeClientHelloUnsigned(hello);
		byte[] signature = sign(signingKey, signedBytes);
		byte[] encoded = encodeClientHelloUnsigned(new ClientHello(movie, certificate, ecdhKeyPair.getPublic().getEncoded(), ciphersuites, nonce, signature, null));
		return new ClientHello(movie, certificate, ecdhKeyPair.getPublic().getEncoded(), ciphersuites, nonce, signature, encoded);
	}

	static ServerHello createServerHello(String movie, boolean clientCertificateOk, Certificate certificate,
										 KeyPair ecdhKeyPair, String ciphersuite, byte[] nonce,
										 byte[] clientChallengeResponse, PrivateKey signingKey)
			throws GeneralSecurityException, IOException {
		ServerHello hello = new ServerHello(movie, clientCertificateOk, certificate, ecdhKeyPair.getPublic().getEncoded(),
				ciphersuite, nonce, clientChallengeResponse, null, null);
		byte[] signedBytes = encodeServerHelloUnsigned(hello);
		byte[] signature = sign(signingKey, signedBytes);
		byte[] encoded = encodeServerHelloUnsigned(new ServerHello(movie, clientCertificateOk, certificate, ecdhKeyPair.getPublic().getEncoded(),
				ciphersuite, nonce, clientChallengeResponse, signature, null));
		return new ServerHello(movie, clientCertificateOk, certificate, ecdhKeyPair.getPublic().getEncoded(),
				ciphersuite, nonce, clientChallengeResponse, signature, encoded);
	}

	static byte[] encodeClientHello(ClientHello hello) throws IOException {
		return encodeClientHelloUnsigned(hello);
	}

	static ClientHello parseClientHello(byte[] bytes) throws Exception {
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
		int type = in.readUnsignedByte();
		int version = in.readUnsignedByte();
		if (type != CLIENT_HELLO || version != VERSION) {
			throw new IOException("Invalid SHP ClientHello");
		}
		String movie = readString(in);
		Certificate certificate = readCertificate(in);
		byte[] ecdhPublicKey = readBytes(in);
		String[] ciphersuites = readStringList(in);
		byte[] nonce = readBytes(in);
		byte[] signature = readBytes(in);
		ClientHello hello = new ClientHello(movie, certificate, ecdhPublicKey, ciphersuites, nonce, signature, bytes);
		if (!certificate.isValid() || !verify(certificate.publicKey(), encodeClientHelloUnsigned(unsigned(hello)), signature)) {
			throw new GeneralSecurityException("Invalid SHP ClientHello signature");
		}
		return hello;
	}

	static byte[] encodeServerHello(ServerHello hello) throws IOException {
		return encodeServerHelloUnsigned(hello);
	}

	static ServerHello parseServerHello(byte[] bytes) throws Exception {
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
		int type = in.readUnsignedByte();
		int version = in.readUnsignedByte();
		if (type != SERVER_HELLO || version != VERSION) {
			throw new IOException("Invalid SHP ServerHello");
		}
		String movie = readString(in);
		boolean clientCertificateOk = in.readBoolean();
		Certificate certificate = readCertificate(in);
		byte[] ecdhPublicKey = readBytes(in);
		String ciphersuite = readString(in);
		byte[] nonce = readBytes(in);
		byte[] clientChallengeResponse = readBytes(in);
		byte[] signature = readBytes(in);
		ServerHello hello = new ServerHello(movie, clientCertificateOk, certificate, ecdhPublicKey, ciphersuite, nonce, clientChallengeResponse, signature, bytes);
		if (!certificate.isValid() || !verify(certificate.publicKey(), encodeServerHelloUnsigned(unsigned(hello)), signature)) {
			throw new GeneralSecurityException("Invalid SHP ServerHello signature");
		}
		return hello;
	}

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
			throw new IOException("Invalid SHP CSSP");
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

	static SessionKeys deriveSessionKeys(PrivateKey privateKey, byte[] peerPublicKey, String ciphersuite,
										 byte[] clientNonce, byte[] serverNonce, byte[] clientHello, byte[] serverHello)
			throws Exception {
		KeyAgreement agreement = KeyAgreement.getInstance(ECDH_ALGORITHM);
		agreement.init(privateKey);
		agreement.doPhase(decodePublicKey(peerPublicKey), true);
		byte[] sharedSecret = agreement.generateSecret();

		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(clientNonce);
		digest.update(serverNonce);
		byte[] salt = digest.digest();

		digest.reset();
		digest.update(clientHello);
		digest.update(serverHello);
		byte[] transcriptHash = digest.digest();

		byte[] prk = hkdfExtract(salt, sharedSecret);
		byte[] keyBlock = hkdfExpand(prk, concat("SHP RTSSP key schedule ".getBytes(StandardCharsets.UTF_8),
				ciphersuite.getBytes(StandardCharsets.UTF_8), transcriptHash), 64);

		String hmac = requiresExternalMac(ciphersuite) ? "HmacSHA256" : null;
		return new SessionKeys(ciphersuite, Arrays.copyOfRange(keyBlock, 0, 32),
				hmac == null ? null : Arrays.copyOfRange(keyBlock, 32, 64), hmac);
	}

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

	static PublicKey decodePublicKey(byte[] encoded) throws GeneralSecurityException {
		return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encoded));
	}

	static byte[] sign(PrivateKey privateKey, byte[] bytes) throws GeneralSecurityException {
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(privateKey);
		signature.update(bytes);
		return signature.sign();
	}

	static boolean verify(PublicKey publicKey, byte[] bytes, byte[] signatureBytes) throws GeneralSecurityException {
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(publicKey);
		signature.update(bytes);
		return signature.verify(signatureBytes);
	}

	private static ClientHello unsigned(ClientHello hello) {
		return new ClientHello(hello.movie, hello.certificate, hello.ecdhPublicKey, hello.ciphersuites, hello.nonce, null, hello.encoded);
	}

	private static ServerHello unsigned(ServerHello hello) {
		return new ServerHello(hello.movie, hello.clientCertificateOk, hello.certificate, hello.ecdhPublicKey, hello.ciphersuite,
				hello.nonce, hello.clientChallengeResponse, null, hello.encoded);
	}

	private static byte[] encodeClientHelloUnsigned(ClientHello hello) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream data = new DataOutputStream(out);
		data.writeByte(CLIENT_HELLO);
		data.writeByte(VERSION);
		writeString(data, hello.movie);
		writeCertificate(data, hello.certificate);
		writeBytes(data, hello.ecdhPublicKey);
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
		writeCertificate(data, hello.certificate);
		writeBytes(data, hello.ecdhPublicKey);
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

	private static void writeCertificate(DataOutputStream out, Certificate certificate) throws IOException {
		writeString(out, certificate.subject);
		writeBytes(out, certificate.publicKey);
		writeBytes(out, certificate.signature);
	}

	private static Certificate readCertificate(DataInputStream in) throws IOException {
		return new Certificate(readString(in), readBytes(in), readBytes(in));
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
		List<String> values = new ArrayList<String>();
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

	static final class Certificate {
		final String subject;
		final byte[] publicKey;
		final byte[] signature;

		Certificate(String subject, byte[] publicKey, byte[] signature) {
			this.subject = subject;
			this.publicKey = publicKey;
			this.signature = signature;
		}

		PublicKey publicKey() throws GeneralSecurityException {
			return decodePublicKey(publicKey);
		}

		boolean isValid() throws GeneralSecurityException, IOException {
			return verify(publicKey(), certificateSignedBytes(subject, publicKey), signature);
		}
	}

	static final class ClientHello {
		final String movie;
		final Certificate certificate;
		final byte[] ecdhPublicKey;
		final String[] ciphersuites;
		final byte[] nonce;
		final byte[] signature;
		final byte[] encoded;

		ClientHello(String movie, Certificate certificate, byte[] ecdhPublicKey, String[] ciphersuites,
					byte[] nonce, byte[] signature, byte[] encoded) {
			this.movie = movie;
			this.certificate = certificate;
			this.ecdhPublicKey = ecdhPublicKey;
			this.ciphersuites = ciphersuites;
			this.nonce = nonce;
			this.signature = signature;
			this.encoded = encoded;
		}
	}

	static final class ServerHello {
		final String movie;
		final boolean clientCertificateOk;
		final Certificate certificate;
		final byte[] ecdhPublicKey;
		final String ciphersuite;
		final byte[] nonce;
		final byte[] clientChallengeResponse;
		final byte[] signature;
		final byte[] encoded;

		ServerHello(String movie, boolean clientCertificateOk, Certificate certificate, byte[] ecdhPublicKey,
					String ciphersuite, byte[] nonce, byte[] clientChallengeResponse, byte[] signature, byte[] encoded) {
			this.movie = movie;
			this.clientCertificateOk = clientCertificateOk;
			this.certificate = certificate;
			this.ecdhPublicKey = ecdhPublicKey;
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
