const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

const users = [
  { id: 1, username: 'user', password: 'password123', isAdmin: false, role: 'user' },
  { id: 2, username: 'guest', password: 'guest123', isAdmin: false, role: 'guest' },
  { id: 3, username: 'moderator', password: 'mod123', isAdmin: false, role: 'moderator' }
];

// Generate RSA key pair for the challenge
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const HMAC_SECRET = 'super_secret_hmac_key_that_should_not_be_guessed';
const WEAK_SECRET = 'secret'; // Intentionally weak for brute force
const ADMIN_SECRET = 'ultra_secure_admin_only_secret_key_9x7z2m5n';

// Save RSA keys to files for the challenge
const serverDir = path.dirname(__filename);
fs.writeFileSync(path.join(serverDir, 'public_key.pem'), publicKey);
fs.writeFileSync(path.join(serverDir, 'private_key.pem'), privateKey);

console.log('🔑 RSA Keys generated and saved to server directory');
console.log('📄 Public key available at /api/public-key endpoint');

// Helper function to create fake admin check
function fakeAdminCheck(token) {
  // This creates a false sense of security - checking isAdmin but not validating properly
  try {
    const decoded = jwt.decode(token); // Note: decode, not verify!
    return decoded && decoded.isAdmin === true;
  } catch (err) {
    return false;
  }
}

// Route to get public key (for RSA verification in client)
app.get('/api/public-key', (req, res) => {
  res.json({ 
    publicKey: publicKey,
    hint: "This public key is used for RSA signature verification. But what if the algorithm isn't what you expect? 🤔"
  });
});

// Login endpoint with multiple vulnerabilities
app.post('/api/login', (req, res) => {
  const { username, password, stage } = req.body;
  
  const user = users.find(u => u.username === username && u.password === password);
  
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  let token;
  let message = '';
  
  // Different stages with different vulnerabilities
  switch (stage) {
    case 'none':
      // Stage 1: Algorithm "none" vulnerability
      token = jwt.sign(
        { 
          id: user.id, 
          username: user.username, 
          isAdmin: user.isAdmin,
          role: user.role,
          stage: 'none'
        }, 
        '', // Empty secret for "none" algorithm
        { algorithm: 'none', expiresIn: '1h' }
      );
      message = 'Stage 1: Basic token generated. Can you become admin? 🎯';
      break;
      
    case 'weak':
      // Stage 2: Weak HMAC secret (brute forceable)
      token = jwt.sign(
        { 
          id: user.id, 
          username: user.username, 
          isAdmin: user.isAdmin,
          role: user.role,
          stage: 'weak'
        }, 
        WEAK_SECRET,
        { algorithm: 'HS256', expiresIn: '1h' }
      );
      message = 'Stage 2: HMAC signed token. The secret might be... simple? 🔍';
      break;
      
    case 'rsa':
      // Stage 3: RSA signed (vulnerable to HMAC confusion)
      token = jwt.sign(
        { 
          id: user.id, 
          username: user.username, 
          isAdmin: user.isAdmin,
          role: user.role,
          stage: 'rsa'
        }, 
        privateKey,
        { algorithm: 'RS256', expiresIn: '1h' }
      );
      message = 'Stage 3: RSA signed token. Very secure... or is it? 🔐';
      break;
      
    default:
      // Default: Strong HMAC
      token = jwt.sign(
        { 
          id: user.id, 
          username: user.username, 
          isAdmin: user.isAdmin,
          role: user.role,
          stage: 'default'
        }, 
        HMAC_SECRET,
        { algorithm: 'HS256', expiresIn: '1h' }
      );
      message = 'Default: Standard secure token generated 🛡️';
  }

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      isAdmin: user.isAdmin,
      role: user.role
    },
    message,
    hint: getStageHint(stage)
  });
});

function getStageHint(stage) {
  const hints = {
    'none': "💡 Hint: Some algorithms require no verification at all...",
    'weak': "💡 Hint: Sometimes the simplest passwords are used for the most important things.",
    'rsa': "💡 Hint: What if the server expects RSA but you give it something else?",
    'default': "💡 This one is actually secure. Try the other stages!"
  };
  return hints[stage] || "💡 No hints for this stage.";
}

// Middleware to verify JWT with intentional vulnerabilities
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  // Get the stage from the token payload (without verification - vulnerability!)
  let decodedPayload;
  try {
    decodedPayload = jwt.decode(token);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token format' });
  }

  if (!decodedPayload || !decodedPayload.stage) {
    return res.status(401).json({ error: 'Token missing stage information' });
  }

  // Verify based on the stage (with vulnerabilities)
  try {
    let decoded;
    
    switch (decodedPayload.stage) {
      case 'none':
        // Vulnerability: Accept "none" algorithm
        decoded = jwt.verify(token, '', { algorithms: ['none'] });
        break;
        
      case 'weak':
        // Vulnerability: Weak secret
        decoded = jwt.verify(token, WEAK_SECRET, { algorithms: ['HS256'] });
        break;
        
      case 'rsa':
        // Vulnerability: Accept both RSA and HMAC algorithms (key confusion)
        try {
          // Try RSA first
          decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        } catch (rsaError) {
          // If RSA fails, try HMAC with public key as secret (vulnerability!)
          decoded = jwt.verify(token, publicKey, { algorithms: ['HS256'] });
        }
        break;
        
      default:
        // Secure verification
        decoded = jwt.verify(token, HMAC_SECRET, { algorithms: ['HS256'] });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// Protected route - User dashboard
app.get('/api/dashboard', verifyToken, (req, res) => {
  res.json({
    message: `Welcome to your dashboard, ${req.user.username}!`,
    user: req.user,
    timestamp: new Date().toISOString()
  });
});

// Fake admin check endpoint (vulnerable)
app.get('/api/fake-admin', (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  // Vulnerable: Only checks isAdmin claim without proper verification
  if (fakeAdminCheck(token)) {
    res.json({
      message: "🎭 Fake admin access granted! But this isn't the real admin panel...",
      flag: "FAKE{not_the_real_flag}",
      hint: "This was just a distraction. Look for the REAL admin endpoints! 🕵️"
    });
  } else {
    res.status(403).json({ error: 'Admin access required' });
  }
});

// Real admin endpoint (properly protected)
app.get('/api/admin', verifyToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  res.json({
    message: "🎉 Real admin access granted!",
    flag: "JWT{alg0r1thm_c0nfus10n_4nd_n0n3_4tt4ck_m4st3r3d}",
    secretData: {
      totalUsers: users.length,
      serverSecrets: {
        hmacSecret: HMAC_SECRET,
        adminSecret: ADMIN_SECRET
      },
      congratulations: "You've successfully exploited JWT vulnerabilities!"
    }
  });
});

// Hidden super admin endpoint (easter egg)
app.get('/api/super-admin', verifyToken, (req, res) => {
  if (!req.user.isAdmin || req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'Super admin access required' });
  }

  res.json({
    message: "🏆 ULTIMATE ACCESS GRANTED!",
    flag: "JWT{y0u_4r3_th3_jwt_h4ck1ng_m4st3r}",
    secretData: {
      message: "You found the hidden endpoint! Set your role to 'superadmin' in the token.",
      ultimateSecret: "The real treasure was the JWT vulnerabilities we exploited along the way!"
    }
  });
});

// List available endpoints
app.get('/api/endpoints', (req, res) => {
  res.json({
    message: "Available API endpoints",
    endpoints: [
      "POST /api/login - Login with username/password and stage selection",
      "GET /api/dashboard - User dashboard (requires valid token)",
      "GET /api/fake-admin - Fake admin panel (weak validation)",
      "GET /api/admin - Real admin panel (requires isAdmin: true)",
      "GET /api/public-key - Get RSA public key",
      "GET /api/endpoints - This endpoint"
    ],
    stages: [
      "none - Algorithm 'none' vulnerability",
      "weak - Weak HMAC secret",
      "rsa - RSA to HMAC key confusion attack",
      "default - Secure implementation"
    ],
    hints: [
      "🎯 Start with 'none' algorithm attack",
      "🔍 Try brute forcing weak secrets",
      "🔐 Exploit RSA/HMAC key confusion",
      "🕵️ Look for hidden endpoints",
      "🎭 Not all admin panels are real..."
    ]
  });
});

// Root endpoint
app.get('/api', (req, res) => {
  res.json({
    message: "🚀 JWT Tampering Challenge API",
    description: "A multi-stage JWT security challenge with various vulnerabilities",
    documentation: "Visit /api/endpoints for available routes",
    author: "Security Challenge Creator"
  });
});

app.listen(PORT, () => {
  console.log(`🚀 JWT Challenge Server running on http://localhost:${PORT}`);
  console.log(`📚 API Documentation: http://localhost:${PORT}/api/endpoints`);
  console.log(`🎯 Ready for JWT tampering challenges!`);
  console.log('\n🔧 Challenge Stages:');
  console.log('  1. none - Algorithm "none" attack');
  console.log('  2. weak - Weak HMAC secret brute force');
  console.log('  3. rsa - RSA to HMAC key confusion attack');
  console.log('\n💡 Start by logging in with any user and selecting a stage!');
});