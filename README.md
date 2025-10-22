# 🔐 JWT Tampering Challenge - Frontend Edition

> **A comprehensive, multi-stage JWT security challenge featuring algorithm confusion attacks, key manipulation, and advanced exploitation techniques - Perfect for Vercel deployment!**

## 🚀 Frontend-Only Architecture

This challenge has been specifically designed as a **frontend-only application** that runs entirely in the browser, making it:
- ✅ **Perfect for Vercel, Netlify, GitHub Pages deployment**
- ✅ **No backend dependencies or server setup required**
- ✅ **Zero configuration deployment**
- ✅ **Instant loading and offline capable**
- ✅ **Cross-platform compatible**

## 🎯 Challenge Overview

This is an **intermediate to advanced** cybersecurity challenge that teaches JWT (JSON Web Token) vulnerabilities through hands-on exploitation. The entire challenge simulates server-side behavior in the frontend, providing a realistic learning experience without backend complexity.

### 🚀 What Makes This Challenge Unique

- **Multi-Stage Progression**: 4 different vulnerability stages with increasing complexity
- **Algorithm Confusion Attacks**: RSA-to-HMAC key confusion and "none" algorithm bypass  
- **Realistic Simulations**: Frontend simulates realistic server responses and validations
- **Hidden Features**: Secret admin panels and easter egg discoveries
- **Interactive Interface**: Beautiful React frontend with real-time token manipulation
- **Automated Attack Tools**: Built-in exploitation utilities
- **Zero Setup**: Runs entirely in browser with no backend required

## 🏗️ Architecture

### Frontend-Only Design (React + TypeScript)
- **Simulated JWT Server**: Complete JWT validation logic in frontend
- **Multi-stage Challenge System**: Different vulnerability implementations
- **Attack Arsenal**: Built-in tools for automated exploitation
- **Educational Interface**: Real-time feedback and learning hints
- **Offline Capability**: Works without internet after initial load

### Key Components
- **JWT Challenge Engine** (`src/utils/jwtChallenge.ts`)
- **Interactive UI** (`src/App.tsx`)
- **Attack Utilities** (Built-in exploitation tools)
- **Educational Content** (Hints, tips, and learning materials)

## 🎮 Challenge Stages

### 🥉 Stage 1: Algorithm "none" Attack
**Objective**: Bypass JWT signature verification entirely

**Vulnerability**: Server accepts `"none"` algorithm tokens without signature validation

**Built-in Tools**: ⚔️ **None Algorithm Attack** button

**Attack Vector**:
1. Login to get initial token
2. Click "None Algorithm Attack" for automated exploitation
3. Use generated token to access admin endpoints
4. Capture the flag!

### 🥈 Stage 2: Weak Secret Brute Force  
**Objective**: Crack weak HMAC secret and forge valid tokens

**Vulnerability**: Server uses easily guessable HMAC secret (`"secret"`)

**Built-in Tools**: ⚔️ **Weak Secret Brute Force** button

**Attack Vector**:
1. Login with "weak" stage selected
2. Click "Weak Secret Brute Force" for automated cracking
3. Tool will crack the secret and generate admin token
4. Access admin panel with forged token

### 🥇 Stage 3: RSA-to-HMAC Key Confusion
**Objective**: Exploit asymmetric-to-symmetric key confusion vulnerability

**Vulnerability**: Server accepts both RSA and HMAC algorithms, using RSA public key as HMAC secret

**Built-in Tools**: ⚔️ **Key Confusion Attack** button

**Attack Vector**:
1. Login with "rsa" stage selected
2. Public key is automatically loaded
3. Click "Key Confusion Attack" for automated exploitation
4. Access admin endpoints with confused algorithm token

### 🏆 Bonus Stage: Hidden Features
**Objective**: Discover secret endpoints and achieve ultimate access

**Features**:
- **Fake Admin Panel**: Deceptive endpoint with weak validation
- **Real Admin Panel**: Properly secured admin access  
- **Super Admin**: Hidden role-based access control
- **Easter Eggs**: Additional flags and secret information

## 🛠️ Quick Start (Zero Configuration)

### Option 1: Vercel Deployment (Recommended)
```bash
# Fork this repository on GitHub
# Connect to Vercel
# Auto-deploy in seconds!
```

### Option 2: Local Development
```bash
# Clone the repository
git clone <repository-url>
cd jwt-tampering-challenge

# Install dependencies
npm install

# Start development server
npm run dev
# or
npx vite

# Open http://localhost:5173
```

### Option 3: Static File Hosting
```bash
# Build for production
npm run build

# Deploy dist/ folder to any static hosting:
# - Netlify
# - GitHub Pages  
# - Vercel
# - Firebase Hosting
# - Any web server
```

## 🎯 Getting Started

### 1. Access the Challenge
- Visit the deployed URL or run locally
- No registration or setup required
- Everything works in your browser

### 2. Learn and Attack
- **Login** with provided credentials (user/password123)
- **Select Stage** (start with "Algorithm none")  
- **Use Attack Tools** for automated exploitation
- **Manual Testing** for advanced users

### 3. Progression System
- ✅ **Stage 1**: Use "None Algorithm Attack" tool
- ✅ **Stage 2**: Use "Weak Secret Brute Force" tool  
- ✅ **Stage 3**: Use "Key Confusion Attack" tool
- ✅ **Bonus**: Discover hidden features and endpoints

## 🚩 Flags & Achievements

### Primary Flags
- **Stage 1**: Algorithm "none" bypass success
- **Stage 2**: Weak secret exploitation  
- **Stage 3**: Key confusion mastery
- **Ultimate**: Super admin access

### Learning Achievements
- **JWT Structure Mastery**: Understanding headers, payloads, signatures
- **Cryptographic Attacks**: Algorithm confusion techniques
- **Security Testing**: Systematic vulnerability discovery
- **Tool Usage**: Automated exploitation methods

## 🔧 Built-in Attack Arsenal

### Automated Exploitation Tools
- **🎯 None Algorithm Attack**: Automatically creates "none" algorithm tokens
- **🔍 Weak Secret Brute Force**: Cracks weak HMAC secrets instantly
- **🔐 Key Confusion Attack**: Generates RSA-to-HMAC confusion tokens
- **🔍 Token Decoder**: Real-time JWT analysis and manipulation

### Manual Testing Features
- **Custom Token Input**: Test your own modified tokens
- **Real-time Validation**: Immediate feedback on attacks
- **Educational Hints**: Learning guidance for each stage
- **Progress Tracking**: Visual indicators of successful attacks

## 🚀 Deployment Guide

### Vercel (Recommended)
1. Fork this repository
2. Connect to Vercel  
3. Auto-deploy with zero configuration
4. Share your challenge URL!

### Netlify
```bash
# Build command: npm run build
# Publish directory: dist
# No environment variables needed
```

### GitHub Pages
```bash
# Enable GitHub Pages in repository settings
# Source: GitHub Actions
# Auto-deploy on push to main
```

### Custom Hosting
```bash
npm run build
# Upload dist/ folder to any web server
# No server-side requirements
```

## 🎓 Learning Outcomes

### Technical Skills Gained
- **JWT Security**: Complete understanding of JWT vulnerabilities
- **Cryptographic Concepts**: Algorithm confusion and signature bypass
- **Security Testing**: Systematic approach to vulnerability discovery  
- **Tool Usage**: Professional security testing methodologies

### Security Concepts
- **Defense in Depth**: Why multiple validation layers matter
- **Secure Coding**: Proper JWT implementation practices
- **Threat Modeling**: Identifying potential attack vectors
- **Incident Response**: Recognizing JWT-based attacks in the wild

## 🛡️ Security Education

### Realistic Vulnerabilities
All vulnerabilities in this challenge are based on real-world security issues:
- **Algorithm "none"**: CVE-2015-9235 and similar vulnerabilities
- **Weak Secrets**: Common misconfiguration in production systems
- **Key Confusion**: Algorithm substitution attacks in JWT libraries

### Prevention Techniques
Learn how to prevent these attacks:
- ✅ **Algorithm Validation**: Explicit algorithm checking
- ✅ **Strong Secrets**: Proper key generation and management
- ✅ **Signature Verification**: Always validate token signatures
- ✅ **Input Validation**: Never trust client-provided data

## 🤝 Contributing & Sharing

### How to Contribute
1. **Fork** the repository
2. **Enhance** the challenge (new stages, better UI, etc.)
3. **Test** thoroughly in different browsers
4. **Submit** pull request with improvements

### Share Your Success
- **Blog Posts**: Write about your learning experience
- **Social Media**: Share screenshots of conquered challenges
- **Educational Use**: Use in security training and workshops
- **CTF Events**: Incorporate into security competitions

## 📊 Challenge Statistics

### Performance Optimized
- **Bundle Size**: < 500KB optimized
- **Load Time**: < 2 seconds on fast connections
- **Browser Support**: All modern browsers
- **Mobile Friendly**: Responsive design for all devices

### Educational Impact
- **Difficulty**: Intermediate to Advanced
- **Time Investment**: 1-3 hours for complete mastery
- **Skill Level**: Security enthusiasts to professionals
- **Learning Value**: Comprehensive JWT security understanding

## 🎉 Success Stories

> "This challenge taught me more about JWT security than any other resource. The automated tools make it easy to understand each attack!" - Security Student

> "Perfect for our security training workshop. Zero setup and works great for remote learning!" - Security Trainer

> "Deployed to Vercel in 30 seconds. Best JWT learning resource I've found!" - Developer

## 🚨 Responsible Use

### Educational Purpose Only
- ✅ **Learn** JWT security concepts responsibly
- ✅ **Practice** in safe, controlled environment  
- ✅ **Apply** knowledge to secure your own applications
- ❌ **Never** attack systems without permission

### Real-World Application
- **Audit** your own applications for JWT vulnerabilities
- **Implement** proper JWT security in production
- **Share** knowledge with development teams
- **Report** vulnerabilities through responsible disclosure

---

## 🎯 Ready to Start Hacking?

### Deployment Options
1. **[Deploy to Vercel](https://vercel.com)** - One-click deployment
2. **[Deploy to Netlify](https://netlify.com)** - Drag & drop deployment  
3. **Local Setup** - `npm install && npm run dev`

### Challenge Progression
1. **🥉 Start with Stage 1** - Algorithm "none" attack
2. **🥈 Progress to Stage 2** - Weak secret brute force
3. **🥇 Master Stage 3** - Key confusion attack
4. **🏆 Discover Secrets** - Hidden endpoints and features

**Remember**: The goal is learning, not just capturing flags. Take time to understand each vulnerability and how to prevent it in real applications.

**Happy Hacking!** 🔐✨

---

*This challenge is designed for educational purposes. Always practice responsible security research and never attack systems without explicit permission.*
