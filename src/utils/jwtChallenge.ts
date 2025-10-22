// JWT Challenge Utils - Frontend Only Implementation
import { Base64 } from 'js-base64';

// Simulated RSA key pair for the challenge
export const RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGbXWiK3dQTyCbX5xdE4
yCuYp0yyTnZQHELqmj3+7J+fZZQY2W4xYgP4RdA8v2W5xQJVL4/4YZ1N1hNFwNZN
Gz7v4G8YnZ4BcHK0aQp9F2J5Y9L8Og0F6XL+1gVb5e5sZ3fE7A6pHqJ8F8L2YxY
EKQcmY5rO4h1tNZh3x3qS+F7lO2d1A5nOzL4jK3A3sY8WLQsE5v7xD3aZ2OOd1Q
IzM8J9CXX8xX2xQ8O8TgPOJ5E5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y
-----END PUBLIC KEY-----`;

export const RSA_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
[This would be the private key in a real scenario]
-----END PRIVATE KEY-----`;

// Simulated secrets (increasing complexity)
export const HMAC_SECRET = 'super_secret_hmac_key_that_should_not_be_guessed';
export const WEAK_SECRET = 'jwt123'; // Slightly harder to guess
export const ADMIN_SECRET = 'ultra_secure_admin_only_secret_key_9x7z2m5n';
export const MICROSERVICE_SECRET = 'ms_internal_auth_2024_v3.1.4';
export const LEGACY_SECRET = 'legacy_jwt_key_deprecated_but_still_active';

// Mock user database (more realistic user scenarios)
export const USERS = [
  { id: 1, username: 'user', password: 'password123', isAdmin: false, role: 'user', department: 'general' },
  { id: 2, username: 'guest', password: 'guest123', isAdmin: false, role: 'guest', department: 'visitor' },
  { id: 3, username: 'moderator', password: 'mod123', isAdmin: false, role: 'moderator', department: 'support' },
  { id: 4, username: 'devops', password: 'devops2024!', isAdmin: false, role: 'engineer', department: 'infrastructure' },
  { id: 5, username: 'analyst', password: 'data_science_2024', isAdmin: false, role: 'analyst', department: 'analytics' }
];

// JWT utility functions
export class JWTUtils {
  static createToken(payload: any, secret: string, algorithm: string = 'HS256'): string {
    const header = {
      typ: 'JWT',
      alg: algorithm
    };

    const encodedHeader = Base64.encode(JSON.stringify(header)).replace(/[=]/g, '');
    const encodedPayload = Base64.encode(JSON.stringify(payload)).replace(/[=]/g, '');

    if (algorithm === 'none') {
      return `${encodedHeader}.${encodedPayload}.`;
    }

    // For demo purposes, we'll create a simple signature
    const signature = this.createSignature(`${encodedHeader}.${encodedPayload}`, secret, algorithm);
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  static createSignature(data: string, secret: string, algorithm: string): string {
    // More sophisticated signature creation for realistic attacks
    if (algorithm === 'HS256') {
      // Simple HMAC simulation with actual crypto patterns
      const hash = this.simpleHash(secret + data);
      return Base64.encode(`hmac_${hash}_${data.length}`).replace(/[=]/g, '');
    } else if (algorithm === 'HS512') {
      const hash = this.simpleHash(secret + data + 'HS512');
      return Base64.encode(`hmac512_${hash}_${data.length}`).replace(/[=]/g, '');
    } else if (algorithm === 'RS256') {
      return Base64.encode(`rsa_signature_${this.simpleHash(data)}`).replace(/[=]/g, '');
    } else if (algorithm === 'ES256') {
      return Base64.encode(`ecdsa_signature_${this.simpleHash(data)}`).replace(/[=]/g, '');
    }
    return '';
  }

  static simpleHash(input: string): string {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
      const char = input.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(16);
  }

  static decodeToken(token: string): { header: any, payload: any, signature: string } | null {
    try {
      const parts = token.split('.');
      if (parts.length < 2) return null;

      const header = JSON.parse(Base64.decode(parts[0]));
      const payload = JSON.parse(Base64.decode(parts[1]));
      const signature = parts[2] || '';

      return { header, payload, signature };
    } catch (error) {
      return null;
    }
  }

  static verifyToken(token: string, secret: string, expectedAlgorithm?: string): any {
    const decoded = this.decodeToken(token);
    if (!decoded) throw new Error('Invalid token format');

    const { header, payload, signature } = decoded;

    // Check token expiration (with bypass vulnerability)
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      // Vulnerability: Allow expired tokens with special claims
      if (!payload.bypassExp && !payload.serviceAccount) {
        throw new Error('Token expired');
      }
    }

    // Algorithm validation (with intentional vulnerabilities)
    if (expectedAlgorithm && header.alg !== expectedAlgorithm) {
      // Vulnerability: Allow algorithm confusion in specific cases
      if (!(expectedAlgorithm === 'RS256' && header.alg === 'HS256') &&
          !(expectedAlgorithm === 'HS256' && header.alg === 'HS512') &&
          !(header.alg === 'none' && payload.debug === true)) {
        throw new Error('Algorithm mismatch');
      }
    }

    // Signature verification with multiple vulnerabilities
    if (header.alg === 'none') {
      // Vulnerability: Accept "none" algorithm with conditions
      if (payload.debug === true || payload.testing === true) {
        return payload;
      }
      throw new Error('None algorithm not allowed');
    }

    // Check for critical claims bypass
    if (header.crit && Array.isArray(header.crit)) {
      // Vulnerability: Ignore critical claims if "legacy" mode is set
      if (!payload.legacy) {
        throw new Error('Critical claims not supported');
      }
    }

    const expectedSignature = this.createSignature(
      `${token.split('.')[0]}.${token.split('.')[1]}`,
      secret,
      header.alg
    );

    if (signature !== expectedSignature) {
      throw new Error('Invalid signature');
    }

    return payload;
  }
}

// Challenge API simulator
export class ChallengeAPI {
  private static instance: ChallengeAPI;

  static getInstance(): ChallengeAPI {
    if (!ChallengeAPI.instance) {
      ChallengeAPI.instance = new ChallengeAPI();
    }
    return ChallengeAPI.instance;
  }

  async login(username: string, password: string, stage: string): Promise<any> {
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 800));

    const user = USERS.find(u => u.username === username && u.password === password);
    
    if (!user) {
      throw new Error('Invalid credentials');
    }

    let token: string;
    let message = '';
    let hint = '';

    // Add common claims for all tokens
    const basePayload = {
      id: user.id,
      username: user.username,
      isAdmin: user.isAdmin,
      role: user.role,
      department: user.department,
      stage: stage,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      iss: 'jwt-challenge-platform',
      aud: 'challenge-participants'
    };

    switch (stage) {
      case 'none':
        token = JWTUtils.createToken({
          ...basePayload,
          debug: true, // Key for none algorithm bypass
        }, '', 'none');
        message = '🥉 Alpha Protocol: Debug token generated. Exploitation window detected! 🎯';
        hint = '💡 Hint: Debug mode tokens have special properties. ';
        break;

      case 'weak':
        token = JWTUtils.createToken({
          ...basePayload,
          legacy: true, // Enables additional bypass
        }, WEAK_SECRET, 'HS256');
        message = '🥈 Beta Protocol: Legacy system token. Security through obscurity? 🔍';
        hint = '💡 Hint: Legacy systems often use predictable secrets. Try common JWT-related passwords.';
        break;

      case 'rsa':
        token = JWTUtils.createToken({
          ...basePayload,
          microservice: true,
        }, RSA_PRIVATE_KEY, 'RS256');
        message = '🥇 Gamma Protocol: Microservice token with RSA signing. Inter-service communication secured? �';
        hint = '💡 Hint: Microservices sometimes accept multiple signature algorithms for compatibility.';
        break;

      case 'advanced':
        // New advanced stage with multiple vulnerabilities
        token = JWTUtils.createToken({
          ...basePayload,
          serviceAccount: true,
          bypassExp: false,
          permissions: ['read:users', 'read:data'],
          crit: ['permissions', 'serviceAccount'] // Critical claims
        }, MICROSERVICE_SECRET, 'HS512');
        message = '💎 Delta Protocol: Service account token with critical claims. Enterprise-grade security? ⚡';
        hint = '💡 Hint: Service accounts have special privileges. Critical claims might be... critical.';
        break;

      case 'nightmare':
        // Ultra-difficult stage
        const nightmarePayload = {
          ...basePayload,
          nested: {
            auth: {
              level: 'standard',
              escalation: false,
              context: {
                environment: 'production',
                features: ['basic_access']
              }
            }
          },
          meta: {
            version: '2.1.0',
            deprecated: ['role_elevation'],
            experimental: ['context_switching']
          }
        };
        token = JWTUtils.createToken(nightmarePayload, LEGACY_SECRET, 'ES256');
        message = '💀 Omega Protocol: Next-gen token with nested authorization context. Quantum-resistant? 🌌';
        hint = '💡 Hint: Modern systems have complex authorization models. Sometimes the old ways still work...';
        break;

      default:
        token = JWTUtils.createToken(basePayload, HMAC_SECRET, 'HS256');
        message = '🛡️ Secure Protocol: Production-ready token with proper security measures 🛡️';
        hint = '💡 This one is actually secure. Try the vulnerability stages for practice!';
    }

    return {
      token,
      user: {
        id: user.id,
        username: user.username,
        isAdmin: user.isAdmin,
        role: user.role,
        department: user.department
      },
      message,
      hint
    };
  }

  async callProtectedEndpoint(endpoint: string, token: string): Promise<any> {
    // Simulate network delay with variability
    await new Promise(resolve => setTimeout(resolve, 200 + Math.random() * 400));

    if (!token) {
      throw new Error('No token provided');
    }

    const decoded = JWTUtils.decodeToken(token);
    if (!decoded) {
      throw new Error('Invalid token format');
    }

    const { payload } = decoded;

    try {
      let verifiedPayload: any;

      switch (endpoint) {
        case 'dashboard':
          verifiedPayload = this.verifyTokenForEndpoint(token, payload.stage);
          return {
            message: `Welcome to your dashboard, ${verifiedPayload.username}!`,
            user: verifiedPayload,
            timestamp: new Date().toISOString(),
            sessionInfo: {
              department: verifiedPayload.department,
              permissions: verifiedPayload.permissions || ['read:basic'],
              lastAccess: new Date().toISOString()
            }
          };

        case 'fake-admin':
          // Vulnerability: Only checks isAdmin claim without proper verification
          if (payload.isAdmin === true) {
            return {
              message: "🎭 Fake admin access granted! But this isn't the real admin panel...",
              flag: "FAKE{n0t_th3_r34l_fl4g_k33p_l00k1ng}",
              hint: "This was just a distraction. Try the microservice or quantum-admin endpoints! 🕵️",
              redirect: "Real challenges await in advanced endpoints..."
            };
          } else {
            throw new Error('Admin access required (hint: check isAdmin claim)');
          }

        case 'admin':
          verifiedPayload = this.verifyTokenForEndpoint(token, payload.stage);
          if (!verifiedPayload.isAdmin) {
            throw new Error('Admin access required');
          }
          return {
            message: "🎉 Admin access granted! But the real challenges are elsewhere...",
            secretData: {
              message: "Standard admin access achieved",
            }
          };

        case 'super-admin':
          verifiedPayload = this.verifyTokenForEndpoint(token, payload.stage);
          if (!verifiedPayload.isAdmin || (verifiedPayload.role !== 'superadmin' && verifiedPayload.role !== 'admin')) {
            if (!(verifiedPayload.serviceAccount && verifiedPayload.permissions?.includes('admin:full'))) {
              throw new Error('Super admin access required (role: superadmin or admin with serviceAccount)');
            }
          }
          return {
            message: "🏆 Super admin access granted! But the ultimate challenges await...",
            secretData: {
              message: "Super admin access achieved",
              ultimateChallenge: "Ready for the real deal? Try microservice and quantum-admin!"
            }
          };

        case 'microservice':
          // REAL FLAG #1 - Service-level exploitation
          verifiedPayload = this.verifyTokenForEndpoint(token, payload.stage);
          if (!verifiedPayload.microservice && !verifiedPayload.serviceAccount) {
            throw new Error('Microservice authentication required');
          }
          return {
            message: "🔧 MICROSERVICE ACCESS ACHIEVED!",
            flag: "csk{m1cr0s3rv1c3_h4ck3r_s3rv1c3_2_s3rv1c3_pwn3d}",
            data: {
              achievement: "Service-to-Service Authentication Bypassed",
              difficulty: "Intermediate",
              technique: "Service Account Token Manipulation",
              services: ['auth-service', 'user-service', 'data-service'],
              congratulations: "You've mastered service account exploitation! 🎉"
            }
          };

        case 'quantum-admin':
          // REAL FLAG #2 - Ultimate advanced exploitation
          verifiedPayload = this.verifyTokenForEndpoint(token, payload.stage);
          
          // Complex authorization logic
          const hasQuantumAccess = (
            verifiedPayload.nested?.auth?.context?.environment === 'production' &&
            verifiedPayload.nested?.auth?.escalation === true
          ) || (
            verifiedPayload.meta?.experimental?.includes('context_switching') &&
            verifiedPayload.role === 'superadmin'
          ) || (
            verifiedPayload.serviceAccount && 
            verifiedPayload.permissions?.includes('quantum:access')
          );

          if (!hasQuantumAccess) {
            throw new Error('Quantum-level access required (nested auth escalation or experimental features)');
          }

          return {
            message: "🌌 QUANTUM ADMIN ACCESS ACHIEVED!",
            flag: "csk{qu4ntum_l3v3l_n3st3d_4uth_m4st3r_h4ck3r_g0d}",
            quantumData: {
              achievement: "Advanced Nested Authorization Bypass",
              difficulty: "Expert",
              technique: "Complex Payload Structure Manipulation",
              dimensions: ['alpha', 'beta', 'gamma', 'delta', 'omega'],
              realityMatrix: "You've transcended standard JWT exploitation",
              ascension: "Welcome to the quantum realm of authentication bypasses! 🏆"
            }
          };

        case 'time-traveler':
          // Hidden endpoint with time-based vulnerabilities
          verifiedPayload = this.verifyTokenForEndpoint(token, payload.stage);
          
          // Check for expired token bypass
          if (verifiedPayload.exp && verifiedPayload.exp < Math.floor(Date.now() / 1000)) {
            if (!verifiedPayload.bypassExp && !verifiedPayload.serviceAccount) {
              throw new Error('Token expired - unless you know the secret...');
            }
          }

          return {
            message: "⏰ Time manipulation successful!",
            flag: "JWT{t1m3_tr4v3l3r_3xp1r4t10n_byp4ss}",
            temporalData: {
              currentTime: new Date().toISOString(),
              tokenExp: new Date(verifiedPayload.exp * 1000).toISOString(),
              paradox: "How did you access this with an expired token?",
              secret: "Service accounts and bypass flags are timeless..."
            }
          };

        default:
          throw new Error('Endpoint not found. Available: dashboard, fake-admin, admin, super-admin, microservice, quantum-admin, time-traveler');
      }
    } catch (error) {
      throw new Error(`Authentication failed: ${error}`);
    }
  }

  private verifyTokenForEndpoint(token: string, stage: string): any {
    const decoded = JWTUtils.decodeToken(token);
    if (!decoded) throw new Error('Invalid token format');

    const { header, payload } = decoded;

    switch (stage) {
      case 'none':
        // Vulnerability: Accept "none" algorithm
        if (header.alg === 'none') {
          return payload;
        }
        throw new Error('Invalid algorithm for none stage');

      case 'weak':
        // Vulnerability: Weak secret (can be brute forced)
        return JWTUtils.verifyToken(token, WEAK_SECRET, 'HS256');

      case 'rsa':
        // Vulnerability: Accept both RSA and HMAC (key confusion)
        try {
          // Try RSA verification first (would fail in real scenario)
          if (header.alg === 'RS256') {
            // In real scenario, this would use actual RSA verification
            return payload;
          }
          // Fall back to HMAC using public key as secret (vulnerability!)
          else if (header.alg === 'HS256') {
            return JWTUtils.verifyToken(token, RSA_PUBLIC_KEY, 'HS256');
          }
          throw new Error('Unsupported algorithm');
        } catch (error) {
          throw new Error('Token verification failed');
        }

      case 'advanced':
        // Vulnerability: Service account tokens with special privileges
        try {
          if (header.alg === 'HS512') {
            return JWTUtils.verifyToken(token, MICROSERVICE_SECRET, 'HS512');
          }
          // Allow algorithm confusion for advanced stage
          else if (header.alg === 'HS256') {
            return JWTUtils.verifyToken(token, MICROSERVICE_SECRET, 'HS256');
          }
          throw new Error('Unsupported algorithm for advanced stage');
        } catch (error) {
          throw new Error('Advanced token verification failed');
        }

      case 'nightmare':
        // Vulnerability: Legacy secret still works with new complex tokens
        try {
          if (header.alg === 'ES256') {
            // Simulate ES256 verification - in reality this would be complex
            return payload;
          }
          // Fallback to legacy secret (vulnerability!)
          else if (header.alg === 'HS256') {
            return JWTUtils.verifyToken(token, LEGACY_SECRET, 'HS256');
          }
          throw new Error('Unsupported algorithm for nightmare stage');
        } catch (error) {
          throw new Error('Nightmare token verification failed');
        }

      default:
        // Secure verification for default stage
        return JWTUtils.verifyToken(token, HMAC_SECRET, 'HS256');
    }
  }

  getPublicKey(): any {
    return {
      publicKey: RSA_PUBLIC_KEY,
      hint: "This public key is used for RSA signature verification. But what if the algorithm isn't what you expect? 🤔"
    };
  }

  getEndpoints(): any {
    return {
      message: "Available API endpoints",
      endpoints: [
        "login - Login with username/password and stage selection",
        "dashboard - User dashboard (requires valid token)",
        "fake-admin - Fake admin panel (weak validation)",
        "admin - Real admin panel (requires isAdmin: true)",
        "public-key - Get RSA public key",
        "endpoints - This endpoint"
      ],
      stages: [
        "none - Algorithm 'none' vulnerability",
        "weak - Weak HMAC secret",
        "rsa - RSA to HMAC key confusion attack",
        "default - Secure implementation"
      ],
      hints: [
        "🕵️ Look for hidden endpoints",
        "🎭 how i love algos...",
        "🔍 Try brute forcing weak secrets",
        "🔐 You're probably almost there",
      ]
    };
  }
}

// Common JWT attack utilities for educational purposes (Enhanced)
export class JWTAttackUtils {
  static createNoneAlgorithmToken(originalToken: string, modifications: any = {}): string {
    const decoded = JWTUtils.decodeToken(originalToken);
    if (!decoded) throw new Error('Invalid token');

    const newHeader = { ...decoded.header, alg: 'none' };
    const newPayload = { 
      ...decoded.payload, 
      ...modifications,
      debug: true, // Enable debug mode for none algorithm
      testing: true // Additional bypass flag
    };

    const encodedHeader = Base64.encode(JSON.stringify(newHeader)).replace(/[=]/g, '');
    const encodedPayload = Base64.encode(JSON.stringify(newPayload)).replace(/[=]/g, '');

    return `${encodedHeader}.${encodedPayload}.`;
  }

  static createHMACToken(payload: any, secret: string, algorithm: string = 'HS256'): string {
    return JWTUtils.createToken(payload, secret, algorithm);
  }

  static bruteForceWeakSecret(token: string, wordlist: string[] = [
    'jwt123', 'secret', 'password', '123456', 'admin', 'test', 'key', 'jwt', 'token',
    'jwt_secret', 'api_key', 'hmac_key', 'auth_secret', 'default', 'changeme',
    'qwerty', 'letmein', 'welcome', 'monkey', 'dragon'
  ]): string | null {
    for (const secret of wordlist) {
      try {
        JWTUtils.verifyToken(token, secret, 'HS256');
        return secret;
      } catch (error) {
        continue;
      }
    }
    return null;
  }

  static createKeyConfusionToken(originalToken: string, publicKey: string, modifications: any = {}): string {
    const decoded = JWTUtils.decodeToken(originalToken);
    if (!decoded) throw new Error('Invalid token');

    const newPayload = { 
      ...decoded.payload, 
      ...modifications,
      microservice: true // Enable microservice mode
    };

    return JWTUtils.createToken(newPayload, publicKey, 'HS256');
  }

  static createAdvancedToken(originalToken: string, modifications: any = {}): string {
    const decoded = JWTUtils.decodeToken(originalToken);
    if (!decoded) throw new Error('Invalid token');

    const advancedPayload = {
      ...decoded.payload,
      ...modifications,
      serviceAccount: true,
      bypassExp: true,
      permissions: ['read:users', 'write:users', 'admin:full', 'quantum:access'],
      legacy: true
    };

    return JWTUtils.createToken(advancedPayload, MICROSERVICE_SECRET, 'HS512');
  }

  static createNestedExploitToken(originalToken: string): string {
    const decoded = JWTUtils.decodeToken(originalToken);
    if (!decoded) throw new Error('Invalid token');

    const nestedPayload = {
      ...decoded.payload,
      nested: {
        auth: {
          level: 'quantum',
          escalation: true,
          context: {
            environment: 'production',
            features: ['admin_override', 'security_bypass']
          }
        }
      },
      meta: {
        version: '3.0.0',
        experimental: ['context_switching', 'nested_auth'],
        deprecated: []
      },
      role: 'superadmin',
      isAdmin: true
    };

    return JWTUtils.createToken(nestedPayload, LEGACY_SECRET, 'ES256');
  }

  static createExpirationBypassToken(originalToken: string): string {
    const decoded = JWTUtils.decodeToken(originalToken);
    if (!decoded) throw new Error('Invalid token');

    const bypassPayload = {
      ...decoded.payload,
      exp: Math.floor(Date.now() / 1000) - 3600, // Expired 1 hour ago
      bypassExp: true,
      serviceAccount: true,
      isAdmin: true,
      role: 'admin',
      timeTravel: true
    };

    return JWTUtils.createToken(bypassPayload, HMAC_SECRET, 'HS256');
  }
}

export default ChallengeAPI;