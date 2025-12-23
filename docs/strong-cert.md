## 🚀 Complete Guide: Creating Strong Certificates for Proxy Server

Here's a comprehensive step-by-step guide to create **strong, production-ready certificates** with proper SAN support for your proxy server.

### 📋 Prerequisites

- OpenSSL installed (`openssl version`)
- Basic understanding of certificate concepts
- Your `san.conf` file (already updated above)

### 🔐 Step 1: Choose Your Cryptographic Algorithm

**For maximum security (recommended for proxy):**
```bash
# Option A: ECC P-256 (Modern, fast, secure)
openssl ecparam -name prime256v1 -genkey -noout -out proxy-key.pem

# Option B: ECC P-384 (Maximum security)
openssl ecparam -name secp384r1 -genkey -noout -out proxy-key.pem

# Option C: RSA 4096 (Traditional, widely supported)
openssl genrsa -out proxy-key.pem 4096
```

### 📄 Step 2: Create Certificate Signing Request (CSR)

```bash
# Generate CSR with SAN extensions
openssl req -new \
  -key proxy-key.pem \
  -out proxy.csr \
  -config certs/san.conf \
  -extensions v3_req
```

**Verify CSR contains SAN:**
```bash
openssl req -in proxy.csr -text -noout | grep -A 10 "Subject Alternative Name"
```

### 🏛️ Step 3: Create Certificate Authority (CA) - For Self-Signed

**Option A: Self-Signed Certificate (Development/Testing)**
```bash
# Create self-signed certificate valid for 365 days
openssl x509 -req \
  -in proxy.csr \
  -signkey proxy-key.pem \
  -out proxy-cert.pem \
  -days 365 \
  -extensions v3_req \
  -extfile certs/san.conf \
  -sha256
```

**Option B: Create Internal CA (Production-Ready)**

1. **Create CA Private Key:**
```bash
openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
```

2. **Create CA Certificate:**
```bash
openssl req -new -x509 \
  -key ca-key.pem \
  -out ca-cert.pem \
  -days 3650 \
  -subj "/C=US/ST=California/L=San Francisco/O=Spooky Proxy CA/OU=Certificate Authority/CN=Spooky Proxy Root CA" \
  -sha256
```

3. **Sign Your Proxy Certificate with CA:**
```bash
openssl x509 -req \
  -in proxy.csr \
  -CA ca-cert.pem \
  -CAkey ca-key.pem \
  -CAcreateserial \
  -out proxy-cert.pem \
  -days 365 \
  -extensions v3_req \
  -extfile certs/san.conf \
  -sha256
```

### 🔍 Step 4: Verify Certificate

**Check certificate details:**
```bash
openssl x509 -in proxy-cert.pem -text -noout
```

**Verify SAN extensions:**
```bash
openssl x509 -in proxy-cert.pem -text -noout | grep -A 5 "Subject Alternative Name"
```

**Check certificate validity:**
```bash
openssl x509 -in proxy-cert.pem -noout -dates
```

**Verify against CA (if using internal CA):**
```bash
openssl verify -CAfile ca-cert.pem proxy-cert.pem
```

### 📦 Step 5: Convert to Required Formats

**For Rust/QUIC applications (DER format):**
```bash
# Convert PKCS#8 key to DER (required for rustls)
openssl pkcs8 -in proxy-key-pkcs8.pem -topk8 -nocrypt -outform DER -out proxy-key.der

# Convert certificate to DER
openssl x509 -in proxy-cert.pem -outform DER -out proxy-cert.der
```

> **⚠️ Important:** Rustls requires PKCS#8 formatted private keys. Always convert EC keys with `openssl pkcs8 -topk8 -nocrypt` before use.

**For web servers (PEM format):**
```bash
# Create full chain (cert + CA)
cat proxy-cert.pem ca-cert.pem > proxy-fullchain.pem
```

### 🔒 Step 6: Security Best Practices

**Set proper permissions:**
```bash
# Private key should be readable only by owner
chmod 600 proxy-key.pem proxy-key.der

# Certificates can be world-readable
chmod 644 proxy-cert.pem proxy-cert.der ca-cert.pem
```

**Backup securely:**
```bash
# Create encrypted backup
tar -czf certs-backup-$(date +%Y%m%d).tar.gz \
  proxy-key.pem proxy-cert.pem ca-cert.pem ca-key.pem

# Encrypt with GPG
gpg -c certs-backup-$(date +%Y%m%d).tar.gz
```

### 🚀 Step 7: Integration with Your Proxy

**For your Rust proxy server:**
```rust
// Example integration (adapt to your code)
let cert = std::fs::read("certs/proxy-cert.der")?;
let key = std::fs::read("certs/proxy-key.der")?;

// Use with your TLS configuration
// (Specific implementation depends on your QUIC/TLS library)
```

**Environment Variables:**
```bash
export PROXY_CERT_PATH="certs/proxy-cert.der"
export PROXY_KEY_PATH="certs/proxy-key.der"
export CA_CERT_PATH="certs/ca-cert.pem"
```

### 🔄 Step 8: Certificate Renewal

**Check expiry:**
```bash
openssl x509 -in proxy-cert.pem -noout -enddate
```

**Renew certificate:**
```bash
# Generate new CSR
openssl x509 -x509toreq \
  -in proxy-cert.pem \
  -signkey proxy-key.pem \
  -out renewed.csr

# Sign with CA
openssl x509 -req \
  -in renewed.csr \
  -CA ca-cert.pem \
  -CAkey ca-key.pem \
  -CAcreateserial \
  -out renewed-cert.pem \
  -days 365 \
  -extensions v3_req \
  -extfile certs/san.conf \
  -sha256
```

### 🧪 Testing Your Certificate

**Test with OpenSSL:**
```bash
# Test server connection
openssl s_client -connect localhost:443 -servername proxy.spooky.local -CAfile ca-cert.pem
```

**Test SAN validation:**
```bash
# Should work for all SAN entries
curl -v https://proxy.spooky.local --cacert ca-cert.pem
curl -v https://localhost --cacert ca-cert.pem
curl -v https://127.0.0.1 --cacert ca-cert.pem
```

### 📁 File Organization

```
certs/
├── san.conf              # SAN configuration
├── proxy-key.pem         # Private key (PEM)
├── proxy-key.der         # Private key (DER)
├── proxy-cert.pem        # Certificate (PEM)
├── proxy-cert.der        # Certificate (DER)
├── proxy.csr             # Certificate Signing Request
├── ca-key.pem            # CA Private Key
├── ca-cert.pem           # CA Certificate
└── proxy-fullchain.pem   # Full chain for web servers
```

### ⚠️ Security Notes

- **Never commit private keys** to version control
- **Use strong passphrases** if encrypting keys
- **Rotate certificates** regularly (90-365 days)
- **Monitor certificate expiry** in production
- **Use HSTS** headers for additional security
- **Consider certificate pinning** for high-security applications

### 🐛 Troubleshooting

**"failed to parse private key as RSA, ECDSA, or EdDSA"**
- **Cause:** Private key not in PKCS#8 format (common with `openssl ecparam` generated keys)
- **Fix:** Convert to PKCS#8: `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pkcs8.pem`
- **Prevention:** Use the provided Makefile targets which handle this automatically

**"certificate verify failed"**
- **Cause:** Certificate doesn't match hostname or missing SAN entries
- **Fix:** Add hostname to `certs/san.conf` and regenerate certificates

**Connection refused / timeout**
- **Cause:** Backend servers not running or wrong addresses
- **Fix:** Check backend server status and configuration in `config/config.yaml`

This guide gives you **enterprise-grade certificate management** suitable for production proxy servers with proper SAN support, strong cryptography, and comprehensive validation.
