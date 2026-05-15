# PROJECT 1 PART 1 - 2 - 3

Eléa-Rose Thomas 76156 | Vicente Ribeiro 72990

## Part 1 - RTSSP Real-Time Special Stream Protocol

RTSSP is a real-time encrypted media streaming protocol over UDP. The server streams movie frames with encryption, and a transparent proxy receives, decrypts, and forwards packets to local clients. Both the server and proxy verify packet integrity with optional MAC authentication.

### Cryptography

- **Encryption algorithms**: `AES/GCM/NoPadding`, `CHACHA20-Poly1305`, `AES/CTR/NoPadding`
- **Authentication**: `HmacSHA256` (used for AES/CTR; AEAD modes include authentication tags)
- **Configuration**: Cipher suite, key, and optional MAC key defined in `Cryptoconfig.conf`
- **Key encoding**: Hexadecimal, Base64, or plain text formats supported

### Packet Format

All RTSSP packets are binary with the structure:

```text
uint8 config_name_length ||
uint8[config_name_length] config_name ||
uint8[iv_size] iv ||
uint8[] ciphertext ||
uint8[mac_length] hmac (optional)
```

The ciphertext contains the encrypted movie frame payload.

### Configuration File

The `Cryptoconfig.conf` file defines available cipher configurations using XML-like sections:

```ini
<section_name>
ciphersuite: AES/GCM/NoPadding
key: <hex_or_base64_encoded_key>
hmac: HmacSHA256          // optional
mackey: <hex_or_base64_encoded_key>  // required if hmac is specified
</section_name>
```

The section name is used as the config identifier in the packet header and must also exist as `<moviename>.encrypted` for the server to load the configuration.

### How to Compile Part 1

```bash
cd Part1-RTSSP/SpecialRealTimeMediaStreaming/hjStreamServer
javac hjStreamServer.java

cd ../hjUDPproxy
javac hjUDPproxy.java
```

### How to Run Part 1

Start the server first. It reads movie frames from the .dat file and streams them with configured encryption:

```bash
cd Part1-RTSSP/SpecialRealTimeMediaStreaming/hjStreamServer
java hjStreamServer <movie_file> <destination_ip> <destination_port>
```

**Example:**
```bash
java hjStreamServer ../../../movies/cars.dat localhost 8888
```

Then start the proxy in another terminal. It receives encrypted packets from the server, decrypts them, and forwards to the local client endpoint:

```bash
cd Part1-RTSSP/SpecialRealTimeMediaStreaming/hjUDPproxy
java hjUDPproxy
```

The proxy reads `remote` and `localdelivery` endpoints from `config.properties`.

### Demo Instructions - Part 1

1. **Setup**: Ensure `Cryptoconfig.conf` is in both the server and proxy directories with matching cipher suite configurations.

2. **Terminal 1 - Start the server**:
   ```bash
   cd Part1-RTSSP/SpecialRealTimeMediaStreaming/hjStreamServer
   java hjStreamServer ../../../movies/cars.dat localhost 8888
   ```

3. **Terminal 2 - Start the proxy**:
   ```bash
   cd Part1-RTSSP/SpecialRealTimeMediaStreaming/hjUDPproxy
   java hjUDPproxy
   ```

4. **Terminal 3 - Play the stream** (optional, requires VLC or similar player):
   ```bash
   vlc udp://localhost:7777
   ```
   Or configure your player to listen on the endpoint specified in `config.properties` under `localdelivery`.

5. **Monitor the streams**: Both server and proxy output progress indicators (`:` for server frames, `.` for proxy packets) to the terminal.

6. **Stop and review logs**: Press `Ctrl+C` in the proxy terminal to stop and generate statistics log. Server logs are written automatically when the stream finishes.

## Part 2 - SHP Secure Handshake

SHP is a small UDP handshake layer inspired by TLS/DTLS 1.3. It runs before RTSSP media packets are transmitted. The proxy starts the handshake, both sides authenticate signed hello messages, establish an ECDH shared secret on `secp256r1`, derive RTSSP keys with HKDF-SHA256, and only then the server starts sending encrypted movie frames.

### Cryptography

- **Public keys**: ECC on `secp256r1`
- **Signatures**: `SHA256withECDSA`
- **Key establishment**: ECDH using fresh ephemeral EC keys
- **KDF**: HKDF-SHA256 over the ECDH secret, client nonce, server nonce, and handshake transcript hash
- **Offered RTSSP ciphersuites**: `AES/GCM/NoPadding`, `CHACHA20-Poly1305`, `AES/CTR/NoPadding`
- **Authentication**: `AES/CTR/NoPadding` derives and uses `HmacSHA256`; AEAD suites rely on their built-in authentication tag

### SHP Message Formats

All SHP messages are binary and start with:

```text
uint8 message_type || uint8 version
```

Variable fields use `uint16 length || bytes`.

**SHP CLIENT_HELLO** (`message_type = 1`):

```text
type || version ||
movie_name ||
client_certificate(subject, public_key, self_signature) ||
client_ecdh_public_key ||
ciphersuite_list ||
client_nonce ||
ecdsa_signature
```

The proxy signs all ClientHello fields before `ecdsa_signature`. The server verifies the client certificate and the ClientHello signature using the certificate public key.

**SHP SERVER_HELLO** (`message_type = 2`):

```text
type || version ||
confirmed_movie_name ||
client_certificate_ok ||
server_certificate(subject, public_key, self_signature) ||
server_ecdh_public_key ||
selected_ciphersuite ||
server_nonce ||
response_to_client_nonce ||
ecdsa_signature
```

The streaming server signs all ServerHello fields before `ecdsa_signature`. The proxy verifies the server certificate, ServerHello signature, selected ciphersuite, movie confirmation, and nonce response.

**SHP CSSP** (`message_type = 3`):

```text
type || version ||
selected_ciphersuite ||
iv ||
encrypted_payload ||
optional_hmac
```

The encrypted CSSP payload contains:

```text
movie_name || response_to_server_nonce || START_RTSSP
```

When the streaming server decrypts and validates CSSP, it starts the RTSSP movie transmission with the derived session keys.

### Configuration File

The proxy requires a `config.properties` file with the following settings:

```ini
server: <server_host>:<handshake_port>     # SHP handshake endpoint
remote: <server_host>:<rtssp_port>         # RTSSP streaming endpoint
localdelivery: <client_host>:<client_port> # Local client delivery endpoint
movie: <movie_filename>                    # Movie to request from server
```

Each side also uses certificate and key files:
- `secret.key`: Private key for ECDSA signing and ECDH key exchange
- `Cryptoconfig.conf`: Cipher configuration (similar to Part 1)

### How to Compile Part 2

```bash
cd Part2-SHP/SecureHandshakeProtocol/hjStreamServer
javac hjStreamServerSHP.java

cd ../hjUDPproxy
javac hjUDPproxySHP.java
```

### How to Run Part 2

Start the server first. It accepts optional arguments for the RTSSP port (default: 8888) and SHP handshake port (default: 9999):

```bash
cd Part2-SHP/SecureHandshakeProtocol/hjStreamServer
java hjStreamServerSHP <movie_file> <bind_ip> [<rtssp_port> [<shp_port>]]
```

**Example:**
```bash
java hjStreamServerSHP ../../../movies/cars.dat localhost 8888 9999
```

Then start the proxy in another terminal. It performs the SHP handshake, derives session keys, and streams the encrypted RTSSP content:

```bash
cd Part2-SHP/SecureHandshakeProtocol/hjUDPproxy
java hjUDPproxySHP
```

The proxy reads server, remote, localdelivery, and movie from `config.properties`.

### Demo Instructions - Part 2

1. **Setup**: Ensure both server and proxy directories contain:
   - `Cryptoconfig.conf`: Defines available cipher suites for RTSSP post-handshake
   - `secret.key`: Private key file for ECDSA and ECDH operations
   - Proxy also needs `config.properties` with proper endpoint configuration

2. **Terminal 1 - Start the SHP server**:
   ```bash
   cd Part2-SHP/SecureHandshakeProtocol/hjStreamServer
   java hjStreamServerSHP ../../../movies/cars.dat localhost 8888 9999
   ```
   The server listens on port 9999 for SHP handshake and port 8888 for RTSSP streaming.

3. **Terminal 2 - Start the SHP proxy**:
   ```bash
   cd Part2-SHP/SecureHandshakeProtocol/hjUDPproxy
   java hjUDPproxySHP
   ```
   The proxy will:
   - Initiate SHP CLIENT_HELLO handshake with the server
   - Receive and verify SHP SERVER_HELLO response
   - Derive shared session keys using ECDH and HKDF-SHA256
   - Send encrypted CSSP handshake completion message
   - Begin proxying encrypted RTSSP streams from server to client

4. **Terminal 3 - Play the stream** (optional, requires VLC or similar player):
   ```bash
   vlc udp://localhost:7777
   ```
   Or configure your player to listen on the endpoint specified in `config.properties` under `localdelivery`.

5. **Monitor the handshake and streams**: 
   - Server displays progress during SHP handshake negotiation
   - Proxy outputs progress indicators during handshake and stream forwarding
   - Both output certificate verification and key derivation information
   - Watch for any authentication or validation errors in the terminal output

6. **Stop and review logs**: Press `Ctrl+C` in the proxy terminal to stop and generate statistics log. Server logs are written when the stream finishes. Check:
   - `hjStreamServerSHP.stats.log`: Server performance and transmission stats
   - `hjUDPproxySHP.stats.log`: Proxy handshake metrics and stream forwarding statistics

## Part 3 - PQ-SHP Post-Quantum Secure Handshake

PQ-SHP is a post-quantum resistant variant of the Secure Handshake Protocol (SHP) designed to protect against future quantum computing threats. It replaces classical elliptic curve cryptography with NIST-standardized post-quantum algorithms while maintaining compatibility with RTSSP encryption.

### Quantum-Safe Cryptography

- **Digital Signatures**: Crystals-Dilithium (ML-DSA-65) - NIST FIPS 204
  - Public Key: 1,312 bytes | Signature: 2,420 bytes | Level 3 security
- **Key Agreement**: Crystals-Kyber (ML-KEM-768) - NIST FIPS 203
  - Public Key: 1,184 bytes | Ciphertext: 1,088 bytes | Level 3 security
- **Symmetric Encryption**: AES-GCM, ChaCha20-Poly1305 (unchanged - already quantum-safe)
- **Key Derivation**: HKDF-SHA256 (unchanged)

### Protocol Characteristics

- **Protocol Version**: 2 (vs. 1 for classical SHP)
- **Quantum Resistance**: ✅ Protected against quantum computing threats
- **Backward Compatibility**: Version field allows co-existence with SHP v1
- **Handshake Size**: ~8,500 bytes (17x larger than classical, acceptable for infrequent handshakes)
- **Handshake Time**: ~6-15 ms (vs 3-8 ms for classical SHP)
- **Streaming Impact**: <0.5% overhead on typical 320 Kbps streams

### How to Compile Part 3

```bash
cd Part3-PQ-SHP/SecureHandshakeProtocol

# Compile core PQ-SHP components
javac PQCryptoProvider.java
javac PQSHPProtocol.java

# Compile server
cd hjStreamServer
cp ../PQCryptoProvider.java ../PQSHPProtocol.java .
javac hjStreamServerPQSHP.java

# Compile proxy
cd ../hjUDPproxy
cp ../PQCryptoProvider.java ../PQSHPProtocol.java .
javac hjUDPproxyPQSHP.java
```

### How to Run Part 3

Start the PQ-SHP server first:

```bash
cd Part3-PQ-SHP/SecureHandshakeProtocol/hjStreamServer
java hjStreamServerPQSHP <movie_file> <bind_ip> <rtssp_port> [pq-shp_port]

# Example:
java hjStreamServerPQSHP ../../../movies/cars.dat localhost 8888 9999
```

Then start the PQ-SHP proxy in another terminal:

```bash
cd Part3-PQ-SHP/SecureHandshakeProtocol/hjUDPproxy
java hjUDPproxyPQSHP
```

The proxy reads server endpoint and other settings from `config.properties`.

### Demo Instructions - Part 3

1. **Setup**: Ensure both server and proxy directories contain:
   - `Cryptoconfig.conf`: Defines cipher suites for RTSSP (same as Part 2)
   - `config.properties` (proxy only): Server endpoint configuration

2. **Terminal 1 - Start the PQ-SHP server**:
   ```bash
   cd Part3-PQ-SHP/SecureHandshakeProtocol/hjStreamServer
   java hjStreamServerPQSHP ../../../movies/cars.dat localhost 8888 9999
   ```
   Output will show:
   - `Waiting for PQ-SHP ClientHello on port 9999...`
   - `Received PQ ClientHello from ...`
   - `Sending PQ-SHP ServerHello with ciphersuite: ...`
   - `PQ-SHP Handshake completed successfully!`
   - `::::::::::` (progress indicators for frame transmission)

3. **Terminal 2 - Start the PQ-SHP proxy**:
   ```bash
   cd Part3-PQ-SHP/SecureHandshakeProtocol/hjUDPproxy
   java hjUDPproxyPQSHP
   ```
   Output will show:
   - `Initiating PQ-SHP handshake with server: localhost:9999`
   - `Sending PQ-SHP ClientHello with 3 ciphersuites`
   - `Received PQ-SHP ServerHello with ciphersuite: ...`
   - `PQ-SHP ready: ... for cars.dat`
   - `..........` (progress indicators for packet forwarding)

4. **Terminal 3 - Play the stream** (optional, requires VLC or similar):
   ```bash
   vlc udp://localhost:7777
   ```

5. **Monitor the handshake and streams**: 
   - Server outputs progress during frame streaming
   - Proxy outputs progress during packet forwarding
   - Watch for successful key agreement and encryption initialization
   - Both show post-quantum cryptography in use

6. **Stop and review logs**: Press `Ctrl+C` in the proxy terminal to generate statistics logs:
   - `hjStreamServerPQSHP.stats.log`: Server performance and transmission stats
   - `hjUDPproxyPQSHP.stats.log`: Proxy handshake metrics and forwarding statistics

### Key Differences from Classical SHP (Part 2)

| Feature | SHP v1 (Part 2) | PQ-SHP v2 (Part 3) |
|---------|-----------------|-------------------|
| Signatures | ECDSA (secp256r1) | Dilithium (ML-DSA-65) |
| Key Agreement | ECDH (secp256r1) | Kyber (ML-KEM-768) |
| Public Key Size | 65 bytes | 1,312 bytes |
| Quantumproof | ❌ | ✅ |
| Message Size | 200 bytes | 4,200 bytes |
| Supported NIST | No (de facto) | Yes (FIPS 203/204) |
| Security Level | Level 2 (128-bit) | Level 3 (192-bit) |

### Design Documentation

For complete technical details including security analysis, threat model, algorithm justification, and performance characteristics, see:

**[PQ-SHP-DESIGN.md](PQ-SHP-DESIGN.md)** - Complete 400+ line design document

For implementation guide, configuration, and deployment instructions, see:

**[Part3-PQ-SHP/README.md](Part3-PQ-SHP/README.md)** - Complete usage and deployment guide

### Design Highlights

**Post-Quantum Security**:
- Dilithium provides resistance against quantum adversaries for digital signatures
- Kyber provides IND-CPA security against quantum adversaries for key agreement
- Symmetric encryption (AES-GCM) is already quantum-safe
- Forward secrecy maintained via ephemeral Kyber keys

**Handshake Flow**:
1. Proxy generates Dilithium identity and ephemeral Kyber keypair
2. Proxy sends ClientHello (signed with Dilithium, contains Kyber public key)
3. Server verifies signature, generates ServerHello with encapsulated Kyber secret
4. Both sides derive identical shared secret using Kyber and HKDF
5. Proxy confirms readiness via encrypted CSSP
6. Streaming begins with derived session keys

**Performance Tradeoffs**:
- Handshake is 17x larger but still acceptable for infrequent use
- Handshake is 2x slower but still <20ms
- Zero impact on streaming performance (negligible overhead)
- Computational cost dominated by Dilithium signing/verification

## Runtime Stats Logs

Each program appends a stats block to a local log file in the directory where it is executed:

- Part 1 server: `hjStreamServer.stats.log`
- Part 1 proxy: `hjUDPproxy.stats.log`
- Part 2 SHP server: `hjStreamServerSHP.stats.log`
- Part 2 SHP proxy: `hjUDPproxySHP.stats.log`
- **Part 3 PQ-SHP server**: `hjStreamServerPQSHP.stats.log`
- **Part 3 PQ-SHP proxy**: `hjUDPproxyPQSHP.stats.log`

Server logs are written when the movie finishes. Proxy logs are written by a shutdown hook, so stop the proxy with `Ctrl+C` when you want the final report.
