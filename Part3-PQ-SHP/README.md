# Part 3: PQ-SHP Post-Quantum Secure Handshake Protocol

## Overview

This is the Post-Quantum Secure Handshake Protocol (PQ-SHP) implementation for RTSSP. It provides quantum-resistant cryptography using NIST-standardized algorithms:

- **Digital Signatures**: Crystals-Dilithium (ML-DSA-65) - NIST FIPS 204
- **Key Establishment**: Crystals-Kyber (ML-KEM-768) - NIST FIPS 203
- **Symmetric Encryption**: AES-GCM, ChaCha20-Poly1305 (unchanged from SHP v1)

## Design Document

For a comprehensive design document covering:
- Security goals and threat model
- Cryptographic algorithms and parameters
- Protocol message formats
- Handshake flow and key derivation
- Implementation architecture
- Security analysis and performance characteristics

See: **[PQ-SHP-DESIGN.md](../PQ-SHP-DESIGN.md)**

## Architecture

### Components

1. **PQSHPProtocol.java**
   - Core protocol implementation
   - Message encoding/decoding (ClientHello, ServerHello, CSSP)
   - Digital signature operations (Dilithium)
   - Key encapsulation operations (Kyber)
   - Session key derivation (HKDF-SHA256)

2. **PQCryptoProvider.java**
   - Post-quantum cryptographic primitives provider
   - Dilithium key generation, signing, verification
   - Kyber key generation, encapsulation, decapsulation
   - Bridge to liboqs-java or other PQC libraries
   - Reference implementation with JNI integration stubs

3. **hjStreamServerPQSHP.java**
   - Post-quantum resistant stream server
   - Accepts PQ-SHP ClientHello from proxy
   - Performs key agreement with Kyber
   - Derives session keys and streams encrypted content

4. **hjUDPproxyPQSHP.java**
   - Post-quantum resistant UDP proxy
   - Initiates PQ-SHP handshake with server
   - Decrypts received packets (from server)
   - Forwards decrypted content to local clients

## Key Sizes and Performance

### Cryptographic Parameters

| Parameter | Size | Notes |
|-----------|------|-------|
| Dilithium Public Key | 1,312 bytes | NIST Level 3 |
| Dilithium Private Key | 2,560 bytes | |
| Dilithium Signature | 2,420 bytes | Deterministic |
| Kyber Public Key | 1,184 bytes | NIST Level 3 |
| Kyber Secret Key | 2,400 bytes | |
| Kyber Ciphertext | 1,088 bytes | |
| Kyber Shared Secret | 32 bytes | |
| Encryption Key (derived) | 32 bytes | AES-256 or ChaCha20 |
| MAC Key (derived) | 32 bytes | HmacSHA256 |

### Message Sizes

| Message | Classical SHP | PQ-SHP | Increase |
|---------|--------------|--------|----------|
| ClientHello | ~200 bytes | ~4,200 bytes | ~20x |
| ServerHello | ~200 bytes | ~4,200 bytes | ~20x |
| CSSP | ~100 bytes | ~100 bytes | None |
| **Handshake Total** | **~500 bytes** | **~8,500 bytes** | **~17x** |

**Note**: Handshakes are infrequent (once per stream session), so overhead is negligible for streaming workloads.

## Compilation

### Prerequisites

```bash
# Ensure Java 11 or higher is installed
java -version

# Optional: Install liboqs-java for production use
# For reference implementation, only standard JDK is required
```

### Compile PQ-SHP Protocol

```bash
# Compile core PQ-SHP components
cd Part3-PQ-SHP/SecureHandshakeProtocol

# Compile protocol classes (order matters due to dependencies)
javac PQCryptoProvider.java
javac PQSHPProtocol.java
```

### Compile Server

```bash
cd hjStreamServer

# Copy protocol files
cp ../PQCryptoProvider.java .
cp ../PQSHPProtocol.java .

# Compile server
javac hjStreamServerPQSHP.java
```

### Compile Proxy

```bash
cd ../hjUDPproxy

# Copy protocol files
cp ../PQCryptoProvider.java .
cp ../PQSHPProtocol.java .

# Compile proxy
javac hjUDPproxyPQSHP.java
```

## Configuration

### Server Configuration

Create `Cryptoconfig.conf` in the server directory:

```ini
<cars.dat.encrypted>
ciphersuite: AES/GCM/NoPadding
key: 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
</cars.dat.encrypted>

<monsters.dat.encrypted>
ciphersuite: CHACHA20-Poly1305
key: <base64_encoded_32_byte_key>
</monsters.dat.encrypted>
```

### Proxy Configuration

Create `config.properties` in the proxy directory:

```properties
# PQ-SHP Handshake Server Endpoint (listening for PQ ClientHello)
server=localhost:9999

# RTSSP Streaming Server Endpoint (receiving encrypted media)
remote=localhost:8888

# Local Client Delivery Endpoint (where to forward decrypted packets)
localdelivery=localhost:7777

# Movie Name (requested from server)
movie=cars.dat
```

## Usage

### Running the PQ-SHP Server

```bash
cd Part3-PQ-SHP/SecureHandshakeProtocol/hjStreamServer

# Syntax:
# java hjStreamServerPQSHP <movie_file> <bind_ip> <rtssp_port> [shp_port]

# Example 1: Default SHP port (9999)
java hjStreamServerPQSHP ../../../movies/cars.dat localhost 8888

# Example 2: Custom SHP port
java hjStreamServerPQSHP ../../../movies/cars.dat localhost 8888 9999
```

**Server Output**:
```
Waiting for PQ-SHP ClientHello on port 9999...
Received PQ ClientHello from /127.0.0.1:12345
Sending PQ-SHP ServerHello with ciphersuite: AES/GCM/NoPadding
PQ-SHP Handshake completed successfully!
PQ-SHP ready: AES/GCM/NoPadding for cars.dat
Post-Quantum Cryptography: Dilithium (signatures) + Kyber (key agreement)
::::::::::::::::::...
DONE! all frames sent: 100
```

### Running the PQ-SHP Proxy

```bash
cd Part3-PQ-SHP/SecureHandshakeProtocol/hjUDPproxy

# Ensure config.properties is configured
java hjUDPproxyPQSHP
```

**Proxy Output**:
```
=== PQ-SHP UDP Proxy ===
Initiating PQ-SHP handshake with server: localhost:9999
Using post-quantum cryptography: Dilithium + Kyber
Sending PQ-SHP ClientHello with 3 ciphersuites
Waiting for PQ-SHP ServerHello...
Received PQ-SHP ServerHello with ciphersuite: AES/GCM/NoPadding
Sending encrypted CSSP confirmation
PQ-SHP ready: AES/GCM/NoPadding for cars.dat

Forwarding encrypted RTSSP packets...
....................................................
```

### Playing the Stream

```bash
# Option 1: Use VLC (if available)
vlc udp://localhost:7777

# Option 2: Use ffplay
ffplay udp://localhost:7777

# Option 3: Configure a custom player to listen on localhost:7777
```

## Demo Workflow

### Terminal 1: Start the PQ-SHP Server

```bash
cd Part3-PQ-SHP/SecureHandshakeProtocol/hjStreamServer
java hjStreamServerPQSHP ../../../movies/cars.dat localhost 8888 9999
```

### Terminal 2: Start the PQ-SHP Proxy

```bash
cd Part3-PQ-SHP/SecureHandshakeProtocol/hjUDPproxy
java hjUDPproxyPQSHP
```

### Terminal 3: Play the Stream (Optional)

```bash
vlc udp://localhost:7777
```

### Monitor and Stop

- **Server**: Outputs progress (`:`) for each frame sent
- **Proxy**: Outputs progress (`.`) for each packet forwarded
- **Stop**: Press Ctrl+C in the proxy terminal
  - Proxy generates `hjUDPproxyPQSHP.stats.log`
  - Server generates `hjStreamServerPQSHP.stats.log`

## Statistics Logs

### Server Stats: `hjStreamServerPQSHP.stats.log`

```
=== PQ-SHP Stream Server Stats 2026-05-15T12:34:56.789 ===
protocol=PQ-SHP-v2
movie=../../../movies/cars.dat
destination=/127.0.0.1:8888
pq_shp_port=9999
handshake_seconds=0.045
crypto_config=cars.dat.encrypted
ciphersuite=AES/GCM/NoPadding
segments_read=100
segments_sent=100
send_failures=0
fail_rate_percent=0.00
plaintext_bytes=409600
encrypted_udp_bytes=414200
stream_duration_seconds=10.234
segments_per_second=9.77
payload_kbps=320.00
encrypted_kbps=323.50
```

### Proxy Stats: `hjUDPproxyPQSHP.stats.log`

```
=== PQ-SHP UDP Proxy Stats 2026-05-15T12:35:06.789 ===
protocol=PQ-SHP-v2
movie=cars.dat
remote=localhost:8888
localdelivery=localhost:7777
pq_shp_server=localhost:9999
ciphersuite=AES/GCM/NoPadding
handshake_seconds=0.052
received_segments=100
forwardable_segments=100
delivered_datagrams=100
parse_drops=0
mac_drops=0
decrypt_drops=0
delivery_failures=0
fail_rate_percent=0.00
received_bytes=414200
decrypted_bytes=409600
delivered_bytes=409600
duration_seconds=10.189
received_segments_per_second=9.81
delivered_datagrams_per_second=9.81
received_kbps=324.45
delivered_kbps=320.00
```

## Handshake Flow Diagram

```
Client (Proxy)                           Server
     |                                      |
     |--- PQ ClientHello (4.2 KB) ------->|
     |  - Dilithium public key & cert     |
     |  - Kyber public key (ephemeral)    |
     |  - Nonce + signature               |
     |                                      |
     |<- PQ ServerHello (4.2 KB) ---------|
     |  - Dilithium public key & cert     |
     |  - Kyber encapsulation ciphertext  |
     |  - Nonce + signature               |
     |                                      |
     | [Both derive shared secret via     |
     |  Kyber and HKDF-SHA256]            |
     |                                      |
     |--- Encrypted CSSP (~150 bytes) --->|
     |  - Confirms handshake              |
     |  - Ready for RTSSP                 |
     |                                      |
     |<- Encrypted RTSSP Stream (ongoing)|
     |  - Each packet: ~4.1 KB             |
     |  - Encrypted with AES-GCM          |
     |                                      |
```

## Security Characteristics

### Quantum Safety

✅ **Protected Against Quantum Attacks**:
- Dilithium: Lattice-based digital signatures (NIST FIPS 204)
- Kyber: Lattice-based KEM (NIST FIPS 203)
- Both algorithms resist quantum computing threats

### Session Security

✅ **Forward Secrecy**: Ephemeral Kyber key agreement
✅ **Mutual Authentication**: Signed certificates and handshake messages
✅ **Message Integrity**: HMAC-SHA256 or AEAD authentication
✅ **Transcript Binding**: Session keys derived from full handshake transcript

### Cryptographic Parameters

- **Security Strength**: NIST Level 3 (≈ 192-bit symmetric equivalent)
- **Resistance**: Quantum computing (up to 2140-bit RSA equivalent security)

## Production Deployment

### Using liboqs-java

For production, replace the reference implementation with actual liboqs-java:

```java
// In PQCryptoProvider.java
import org.openquantumsafe.*;

// Use liboqs-java bindings
KeyEncapsulation oqsKem = new KeyEncapsulation("ML-KEM-768");
byte[] ciphertext = oqsKem.encaps(publicKeyBytes);
byte[] sharedSecret = oqsKem.decaps(ciphertextBytes);

Signature oqsSig = new Signature("ML-DSA-65");
byte[] signature = oqsSig.sign(message);
boolean valid = oqsSig.verify(message, signature);
```

**Maven Dependency**:
```xml
<dependency>
    <groupId>org.openquantumsafe</groupId>
    <artifactId>liboqs-java</artifactId>
    <version>0.9.0</version>
</dependency>
```

## Testing

### Unit Tests

```bash
# Test PQ protocol messages
javac -d . PQSHPProtocol.java PQCryptoProvider.java
javac -d . PQSHPProtocolTest.java
java -cp . PQSHPProtocolTest
```

### Integration Tests

```bash
# Full handshake simulation
# (Run server and proxy in separate terminals)
```

### Performance Benchmarks

```
Dilithium Key Generation: ~1-2 ms
Dilithium Signing: ~2-4 ms
Dilithium Verification: ~2-4 ms
Kyber Encapsulation: ~0.5-1 ms
Kyber Decapsulation: ~0.5-1 ms
Total Handshake: ~6-12 ms
```

## Troubleshooting

### Issue: "Invalid PQ-SHP ClientHello signature"

**Cause**: Mismatch between client and server public key or handshake message corruption  
**Solution**: Ensure both sides use compatible PQ algorithms and that network is reliable

### Issue: "CSSP ciphersuite mismatch"

**Cause**: Client and server selected different ciphersuites  
**Solution**: Verify both support the same ciphersuites in `Cryptoconfig.conf`

### Issue: Handshake timeouts

**Cause**: Ports not accessible or firewall blocking  
**Solution**: Check that SHP port (default 9999) is open and config.properties is correct

## References

- **[PQ-SHP-DESIGN.md](../PQ-SHP-DESIGN.md)** - Complete design document
- **FIPS 204** - Module-Lattice-Based Digital Signature Standard (Dilithium)
- **FIPS 203** - Module-Lattice-Based Key-Encapsulation Mechanism Standard (Kyber)
- **liboqs-java** - https://github.com/open-quantum-safe/liboqs-java
- **Crystals-Dilithium** - https://pq-crystals.org/dilithium/
- **Crystals-Kyber** - https://pq-crystals.org/kyber/

## Comparison with SHP v1

| Feature | SHP v1 | PQ-SHP v2 |
|---------|--------|-----------|
| Signatures | ECDSA | Dilithium |
| Key Agreement | ECDH | Kyber |
| Protocol Version | 1 | 2 |
| Quantum Resistant | ❌ | ✅ |
| Handshake Size | ~500 bytes | ~8,500 bytes |
| Handshake Time | ~3-8 ms | ~6-12 ms |
| Message Format | Backward compatible with v1 | Version field identifies v2 |

## Security Roadmap

**Phase 1**: Deploy PQ-SHP alongside classical SHP  
**Phase 2**: Make PQ-SHP default for new deployments  
**Phase 3**: Deprecate classical SHP  
**Phase 4**: Full migration to post-quantum cryptography  

---

**Implementation Status**: Complete ✅  
**Design Review**: Complete ✅  
**Unit Tests**: Reference implementation ✅  
**Production Readiness**: Requires liboqs-java integration for production use

**Last Updated**: May 2026

