import { useState, useEffect } from 'react'
import './App.css'
import { ChallengeAPI, JWTUtils, JWTAttackUtils } from './utils/jwtChallenge'

interface User {
  id: number;
  username: string;
  isAdmin: boolean;
  role: string;
}

interface LoginResponse {
  token: string;
  user: User;
  message: string;
  hint: string;
}

interface ApiResponse {
  message?: string;
  error?: string;
  flag?: string;
  hint?: string;
  secretData?: any;
  user?: User;
  timestamp?: string;
  congratulations?: string;
}

function App() {
  const [username, setUsername] = useState('user');
  const [password, setPassword] = useState('password123');
  const [stage, setStage] = useState('none');
  const [token, setToken] = useState('');
  const [user, setUser] = useState<User | null>(null);
  const [response, setResponse] = useState<string>('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [customToken, setCustomToken] = useState('');
  const [publicKey, setPublicKey] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);

  const api = ChallengeAPI.getInstance();

  useEffect(() => {
    loadPublicKey();
    setResponse(`🎯 Welcome to the JWT Security Challenge!

Ready to test your skills? Start by:
1. 🔑 Login with any credentials
2. 🎯 Select a challenge stage
3. ⚔️ Use the attack tools to exploit vulnerabilities
4. 🏆 Capture the flags!

💡 Need help? Toggle the hints panel below.`);
  }, []);

  const loadPublicKey = () => {
    const data = api.getPublicKey();
    setPublicKey(data.publicKey);
  };

  const login = async () => {
    try {
      setIsLoading(true);
      const data: LoginResponse = await api.login(username, password, stage);
      
      setToken(data.token);
      setUser(data.user);
      setIsLoggedIn(true);
      setResponse(`✅ ${data.message}\n🎫 Your JWT Token:\n${data.token}\n\n💡 Use the Attack Arsenal or manually modify this token to escalate privileges!`);
    } catch (error: any) {
      setResponse(`❌ Login Failed: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const callAPI = async (endpoint: string, useCustomToken = false) => {
    try {
      setIsLoading(true);
      const authToken = useCustomToken ? customToken : token;
      const data: ApiResponse = await api.callProtectedEndpoint(endpoint, authToken);
      
      let responseText = `✅ ${data.message}`;
      if (data.flag) responseText += `\n\n🚩 FLAG CAPTURED: ${data.flag}`;
      if (data.hint) responseText += `\n\n💡 ${data.hint}`;
      if (data.secretData) responseText += `\n\n🔒 Secret Data Revealed:\n${JSON.stringify(data.secretData, null, 2)}`;
      if (data.user) responseText += `\n\n👤 Authenticated As:\n${JSON.stringify(data.user, null, 2)}`;
      if (data.timestamp) responseText += `\n\n⏰ Access Time: ${data.timestamp}`;
      setResponse(responseText);
    } catch (error: any) {
      setResponse(`❌ Access Denied: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    setToken('');
    setUser(null);
    setIsLoggedIn(false);
    setCustomToken('');
    setResponse('👋 Logged out successfully. Ready for a new challenge?');
  };

  const decodeToken = (tokenToDecode: string) => {
    try {
      const decoded = JWTUtils.decodeToken(tokenToDecode);
      if (!decoded) {
        setResponse('❌ Invalid token format');
        return;
      }
      
      const { header, payload, signature } = decoded;
      
      setResponse(`🔍 JWT Token Analysis:
      
📋 HEADER:
${JSON.stringify(header, null, 2)}

📦 PAYLOAD:
${JSON.stringify(payload, null, 2)}

🔗 SIGNATURE: ${signature || '(none)'}

💡 Exploitation Tip: Try modifying the 'alg' field in the header and 'isAdmin' in the payload!`);
    } catch (error) {
      setResponse(`❌ Token decode error: ${error}`);
    }
  };

  const performNoneAttack = () => {
    if (!token) {
      setResponse('❌ Please login first to get a token');
      return;
    }

    try {
      const attackToken = JWTAttackUtils.createNoneAlgorithmToken(token, { 
        isAdmin: true,
        role: 'admin'
      });
      setCustomToken(attackToken);
      setResponse(`🎯 ALGORITHM "NONE" ATTACK EXECUTED!

🔓 Generated Token: ${attackToken}

⚡ Attack Summary:
• Changed algorithm to "none"
• Set isAdmin: true
• Removed signature requirement

🎯 Next Step: Use this token to access admin endpoints!`);
    } catch (error: any) {
      setResponse(`❌ Attack failed: ${error.message}`);
    }
  };

  const performWeakSecretAttack = () => {
    if (!token) {
      setResponse('❌ Please login first to get a token');
      return;
    }

    try {
      const wordlist = ['secret', 'password', '123456', 'admin', 'test', 'key', 'jwt', 'token'];
      const crackedSecret = JWTAttackUtils.bruteForceWeakSecret(token, wordlist);
      
      if (crackedSecret) {
        const decoded = JWTUtils.decodeToken(token);
        if (decoded) {
          const newPayload = { ...decoded.payload, isAdmin: true, role: 'admin' };
          const attackToken = JWTAttackUtils.createHMACToken(newPayload, crackedSecret);
          setCustomToken(attackToken);
          setResponse(`🎯 Weak Secret Attack Successful!

🔑 Cracked Secret: "${crackedSecret}"
🔓 Forged Token: ${attackToken}

💡 The secret was weak and easily brute-forced!
Try using this token with the admin endpoints!`);
        }
      } else {
        setResponse(`❌ Could not crack the secret with common passwords.
💡 Try expanding the wordlist or this might not be the weak secret stage.`);
      }
    } catch (error: any) {
      setResponse(`❌ Attack failed: ${error.message}`);
    }
  };

  const performKeyConfusionAttack = () => {
    if (!token || !publicKey) {
      setResponse('❌ Please login first and ensure public key is loaded');
      return;
    }

    try {
      const attackToken = JWTAttackUtils.createKeyConfusionToken(token, publicKey, {
        isAdmin: true,
        role: 'superadmin'
      });
      setCustomToken(attackToken);
      setResponse(`🎯 KEY CONFUSION ATTACK EXECUTED!

🔐 Attack Vector: RSA-to-HMAC Algorithm Confusion
🔓 Generated Token: ${attackToken}

⚡ Attack Summary:
• Used RSA public key as HMAC secret
• Changed algorithm from RS256 to HS256
• Set role to 'superadmin'
• Exploited server's algorithm flexibility

🎯 Next Step: Access admin endpoints with confused algorithm!`);
    } catch (error: any) {
      setResponse(`❌ Attack failed: ${error.message}`);
    }
  };

  const performAdvancedServiceAttack = () => {
    if (!token) {
      setResponse('❌ Please login first to get a token');
      return;
    }

    try {
      const attackToken = JWTAttackUtils.createAdvancedToken(token, {
        isAdmin: true,
        role: 'admin'
      });
      setCustomToken(attackToken);
      setResponse(`💎 ADVANCED SERVICE ATTACK EXECUTED!

🔧 Attack Vector: Service Account Privilege Escalation
🔓 Generated Token: ${attackToken}

⚡ Attack Summary:
• Enabled service account mode
• Added comprehensive permissions array
• Set expiration bypass flag
• Changed algorithm to HS512

🎯 Next Step: Access microservice and quantum-admin endpoints!`);
    } catch (error: any) {
      setResponse(`❌ Attack failed: ${error.message}`);
    }
  };

  const performNestedExploitAttack = () => {
    if (!token) {
      setResponse('❌ Please login first to get a token');
      return;
    }

    try {
      const attackToken = JWTAttackUtils.createNestedExploitToken(token);
      setCustomToken(attackToken);
      setResponse(`💀 NESTED AUTHORIZATION BYPASS EXECUTED!

🌌 Attack Vector: Complex Authorization Context Manipulation
🔓 Generated Token: ${attackToken}

⚡ Attack Summary:
• Created nested authorization structure
• Set quantum-level escalation context
• Added experimental feature flags
• Enabled production environment override

🎯 Next Step: Achieve quantum-admin access with nested auth!`);
    } catch (error: any) {
      setResponse(`❌ Attack failed: ${error.message}`);
    }
  };

  return (
    <div className="app">
      <div className="container">
        <header className="header">
          <h1>🔐 Evolved Security Challenge</h1>
          <p className="subtitle">
            Master Evolved vulnerabilities through hands-on exploitation
          </p>
          <div className="badge">Pure • Jawait • Manipulation</div>
        </header>

        <div className="challenge-grid">
          {/* Login Section */}
          <div className="card">
            <h2>🚪 Authentication</h2>
            {!isLoggedIn ? (
              <>
                <div className="form-group">
                  <label>Username:</label>
                  <select value={username} onChange={(e) => setUsername(e.target.value)}>
                    <option value="user">user</option>
                    <option value="guest">guest</option>
                    <option value="moderator">moderator</option>
                  </select>
                </div>
                
                <div className="form-group">
                  <label>Password:</label>
                  <input 
                    type="password" 
                    value={password} 
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={username === 'user' ? 'password123' : username === 'guest' ? 'guest123' : 'mod123'}
                  />
                </div>
                
                <div className="form-group">
                  <label>🎯 Challenge Protocol:</label>
                  <select value={stage} onChange={(e) => setStage(e.target.value)}>
                    <option value="none">🥉 Protocol Alpha: Algorithm Bypass</option>
                    <option value="weak">🥈 Protocol Beta: Secret Extraction</option>
                    <option value="rsa">🥇 Protocol Gamma: Cryptographic Confusion</option>
                    <option value="advanced">💎 Protocol Delta: Advanced Service Exploitation</option>
                    <option value="nightmare">💀 Protocol Omega: Nested Authorization Bypass</option>
                    <option value="default">🛡️ Protocol Secure (Reference)</option>
                  </select>
                </div>
                
                <button onClick={login} className="btn btn-primary" disabled={isLoading}>
                  {isLoading ? '⏳ Logging in...' : '🔑 Login & Get Token'}
                </button>
              </>
            ) : (
              <div className="user-info">
                <h3>👤 Logged in as: {user?.username}</h3>
                <p>🎭 Role: {user?.role}</p>
                <p>🔒 Admin: {user?.isAdmin ? '✅ Yes' : '❌ No'}</p>
                <button onClick={logout} className="btn btn-secondary">
                  🚪 Logout
                </button>
              </div>
            )}
          </div>

          {/* Token Manipulation */}
          <div className="card">
            <h2>🛠️ Token Workshop</h2>
            {token && (
              <>
                <div className="form-group">
                  <label>Current Token:</label>
                  <textarea 
                    value={token} 
                    readOnly 
                    className="token-display"
                    onClick={() => navigator.clipboard.writeText(token)}
                    title="Click to copy"
                  />
                </div>
                <button 
                  onClick={() => decodeToken(token)} 
                  className="btn btn-info"
                >
                  🔍 Decode Current Token
                </button>
              </>
            )}
            
            <div className="form-group">
              <label>Custom Token (for testing):</label>
              <textarea 
                value={customToken}
                onChange={(e) => setCustomToken(e.target.value)}
                placeholder="Paste your modified JWT here..."
                className="token-input"
              />
            </div>
            
            {customToken && (
              <button 
                onClick={() => decodeToken(customToken)} 
                className="btn btn-info"
              >
                🔍 Decode Custom Token
              </button>
            )}
          </div>

          {/* Attack Arsenal */}
          <div className="card arsenal-card">
            <h2>⚔️ Attack Arsenal</h2>
            <div className="attack-tools">
              <button 
                onClick={performNoneAttack}
                className="btn btn-attack"
                disabled={!token || isLoading}
              >
                🎯 Execute None Attack
              </button>
              
              <button 
                onClick={performWeakSecretAttack}
                className="btn btn-attack"
                disabled={!token || isLoading}
              >
                🔍 Brute Force Secrets
              </button>
              
              <button 
                onClick={performKeyConfusionAttack}
                className="btn btn-attack"
                disabled={!token || isLoading}
              >
                🔐 Key Confusion Strike
              </button>

              <button 
                onClick={performAdvancedServiceAttack}
                className="btn btn-attack"
                disabled={!token || isLoading}
              >
                💎 Service Privilege Escalation
              </button>

              <button 
                onClick={performNestedExploitAttack}
                className="btn btn-attack"
                disabled={!token || isLoading}
              >
                � Nested Auth Bypass
              </button>
            </div>
            
            <div className="attack-info">
              <p>💀 Focused exploitation arsenal - 2 real targets</p>
              <p>🎯 Master microservice and quantum-level attacks</p>
            </div>
          </div>

          {/* Target Systems */}
          <div className="card targets-card">
            <h2>🎯 Target Systems</h2>
            <div className="button-grid">
              <button 
                onClick={() => callAPI('dashboard')} 
                className="btn btn-action"
                disabled={!token || isLoading}
              >
                📊 User Dashboard
              </button>
              
              <button 
                onClick={() => callAPI('fake-admin')} 
                className="btn btn-warning"
                disabled={isLoading}
              >
                🎭 Honeypot Admin
              </button>
              
              <button 
                onClick={() => callAPI('admin')} 
                className="btn btn-danger"
                disabled={isLoading}
              >
                👑 Admin Control
              </button>
              
              <button 
                onClick={() => callAPI('super-admin')} 
                className="btn btn-ultimate"
                disabled={isLoading}
              >
                🏆 Root Access
              </button>

              <button 
                onClick={() => callAPI('microservice')} 
                className="btn btn-advanced"
                disabled={isLoading}
              >
                🔧 Microservice API
              </button>

              <button 
                onClick={() => callAPI('quantum-admin')} 
                className="btn btn-quantum"
                disabled={isLoading}
              >
                🌌 Quantum Admin
              </button>
            </div>

            {customToken && (
              <div className="custom-token-section">
                <h3>🧪 Test Custom Payload:</h3>
                <div className="button-grid">
                  <button 
                    onClick={() => callAPI('dashboard', true)} 
                    className="btn btn-test"
                    disabled={isLoading}
                  >
                    📊 Dashboard
                  </button>
                  
                  <button 
                    onClick={() => callAPI('admin', true)} 
                    className="btn btn-test"
                    disabled={isLoading}
                  >
                    👑 Admin
                  </button>
                  
                  <button 
                    onClick={() => callAPI('super-admin', true)} 
                    className="btn btn-test"
                    disabled={isLoading}
                  >
                    🏆 Root
                  </button>

                  <button 
                    onClick={() => callAPI('microservice', true)} 
                    className="btn btn-test"
                    disabled={isLoading}
                  >
                    🔧 Microservice
                  </button>

                  <button 
                    onClick={() => callAPI('quantum-admin', true)} 
                    className="btn btn-test"
                    disabled={isLoading}
                  >
                    🌌 Quantum
                  </button>
                </div>
              </div>
            )}
          </div>
          </div>

          {/* Response Display */}
          <div className="card response-card">
            <h2>📝 Challenge Response</h2>
            {isLoading && <div className="loading">⏳ Processing...</div>}
            <pre className="response-display">{response || 'No response yet. Try logging in!'}</pre>
          </div>

          {/* Public Key Display */}
          {publicKey && (
            <div className="card">
              <h2>🔑 RSA Public Key</h2>
              <textarea 
                value={publicKey}
                readOnly
                className="public-key-display"
                onClick={() => navigator.clipboard.writeText(publicKey)}
                title="Click to copy public key"
              />
              <p className="hint">💡 This public key is used for Stage 3 attacks!</p>
            </div>
          )}


        </div>

        <footer className="footer">
          <p>🎮 Evolved Security Challenge - Advanced Penetration Testing Laboratory</p>
          <p>💡 Educational platform for security professionals and enthusiasts</p>
          <p>🚀 &copy; 2025 All security evolved <br /> @colkimi</p>
        </footer>
      </div>
  )
}

export default App
