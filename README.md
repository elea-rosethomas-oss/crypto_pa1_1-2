# PROJECT 1 PART 1 - 2 - 3

Eléa-Rose Thomas 76156 | Vicente 


## How to Compile

## How to Run

## Demo Instructions

## Part 2 - SHP Secure Handshake

SHP is a small UDP handshake layer inspired by TLS/DTLS 1.3. It runs before RTSSP media packets are transmitted. The proxy starts the handshake, both sides authenticate signed hello messages, establish an ECDH shared secret on `secp256r1`, derive RTSSP keys with HKDF-SHA256, and only then the server starts sending encrypted movie frames.

### Cryptography

- Public keys: ECC on `secp256r1`.
- Signatures: `SHA256withECDSA`.
- Key establishment: ECDH using fresh ephemeral EC keys.
- KDF: HKDF-SHA256 over the ECDH secret, client nonce, server nonce, and handshake transcript hash.
- Offered RTSSP ciphersuites: `AES/GCM/NoPadding`, `CHACHA20-Poly1305`, `AES/CTR/NoPadding`.
- `AES/CTR/NoPadding` also derives and uses `HmacSHA256`; AEAD suites rely on their built-in authentication tag.

### SHP Message Formats

All SHP messages are binary and start with:

```text
uint8 message_type || uint8 version
```

Variable fields use `uint16 length || bytes`.

`SHP CLIENT_HELLO` (`message_type = 1`):

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

`SHP SERVER_HELLO` (`message_type = 2`):

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

`SHP CSSP` (`message_type = 3`):

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

### How to Run Part 2

Compile each side:

```bash
cd Part2-SHP/SecureHandshakeProtocol/hjStreamServer
javac hjStreamServerSHP.java

cd ../hjUDPproxy
javac hjUDPproxySHP.java
```

Start the server first. The fourth argument is the optional SHP handshake port; it defaults to `9999`.

```bash
cd Part2-SHP/SecureHandshakeProtocol/hjStreamServer
java hjStreamServerSHP ../../../movies/cars.dat localhost 8888 9999
```

Then start the proxy:

```bash
cd Part2-SHP/SecureHandshakeProtocol/hjUDPproxy
java hjUDPproxySHP
```

The proxy reads `server`, `remote`, `localdelivery`, and `movie` from `config.properties`.

## Runtime Stats Logs

Each program appends a stats block to a local log file in the directory where it is executed:

- Part 1 server: `hjStreamServer.stats.log`
- Part 1 proxy: `hjUDPproxy.stats.log`
- Part 2 SHP server: `hjStreamServerSHP.stats.log`
- Part 2 SHP proxy: `hjUDPproxySHP.stats.log`

Server logs are written when the movie finishes. Proxy logs are written by a shutdown hook, so stop the proxy with `Ctrl+C` when you want the final report.
