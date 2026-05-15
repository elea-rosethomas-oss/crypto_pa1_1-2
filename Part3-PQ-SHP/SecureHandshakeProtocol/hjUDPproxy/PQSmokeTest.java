import java.security.KeyPair;
import java.util.Arrays;

public class PQSmokeTest {
	public static void main(String[] args) throws Exception {
		PQCryptoProvider provider = new PQCryptoProvider();

		// Client side material
		KeyPair clientIdentity = PQSHPProtocol.generateDilithiumKeyPair();
		KeyPair clientKyber = PQSHPProtocol.generateKyberKeyPair();
		PQSHPProtocol.PQCertificate clientCert = PQSHPProtocol.createPQCertificate("proxy", clientIdentity);
		byte[] clientNonce = PQSHPProtocol.randomNonce();
		PQSHPProtocol.ClientHello clientHello = PQSHPProtocol.createClientHello(
			"cars.dat",
			clientCert,
			clientKyber,
			PQSHPProtocol.DEFAULT_CIPHERSUITES,
			clientNonce,
			clientIdentity.getPrivate()
		);
		PQSHPProtocol.ClientHello parsedClientHello = PQSHPProtocol.parseClientHello(clientHello.encoded);
		if (!Arrays.equals(clientHello.encoded, parsedClientHello.encoded)) {
			throw new IllegalStateException("ClientHello round-trip mismatch");
		}

		// Server side material
		KeyPair serverIdentity = PQSHPProtocol.generateDilithiumKeyPair();
		KeyPair serverKyber = PQSHPProtocol.generateKyberKeyPair();
		PQSHPProtocol.PQCertificate serverCert = PQSHPProtocol.createPQCertificate("streaming-server", serverIdentity);
		byte[] serverNonce = PQSHPProtocol.randomNonce();
		String selectedCiphersuite = PQSHPProtocol.chooseCiphersuite(PQSHPProtocol.DEFAULT_CIPHERSUITES);
		PQSHPProtocol.ServerHello serverHello = PQSHPProtocol.createServerHello(
			"cars.dat",
			true,
			serverCert,
			serverKyber,
			selectedCiphersuite,
			serverNonce,
			PQSHPProtocol.challengeResponse(clientNonce),
			serverIdentity.getPrivate()
		);
		PQSHPProtocol.ServerHello parsedServerHello = PQSHPProtocol.parseServerHello(serverHello.encoded);
		if (!Arrays.equals(serverHello.encoded, parsedServerHello.encoded)) {
			throw new IllegalStateException("ServerHello round-trip mismatch");
		}

		// Session key derivation must match on both sides
		PQSHPProtocol.SessionKeys clientKeys = PQSHPProtocol.deriveSessionKeys(
			clientKyber.getPrivate(),
			serverKyber.getPublic().getEncoded(),
			selectedCiphersuite,
			clientNonce,
			serverNonce,
			clientHello.encoded,
			serverHello.encoded
		);
		PQSHPProtocol.SessionKeys serverKeys = PQSHPProtocol.deriveSessionKeys(
			serverKyber.getPrivate(),
			clientKyber.getPublic().getEncoded(),
			selectedCiphersuite,
			clientNonce,
			serverNonce,
			clientHello.encoded,
			serverHello.encoded
		);

		if (!Arrays.equals(clientKeys.encryptionKey, serverKeys.encryptionKey)) {
			throw new IllegalStateException("Derived encryption keys differ");
		}
		if (clientKeys.hmacAlgorithm != null && !Arrays.equals(clientKeys.macKey, serverKeys.macKey)) {
			throw new IllegalStateException("Derived MAC keys differ");
		}

		System.out.println("PQ-SHP smoke test passed: signatures, parsing, and shared secrets are consistent.");
	}
}

