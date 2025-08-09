# MentorIQ S-MVP Quick Start Guide

## 🚀 5-Minute Setup

### Prerequisites
- Python 3.11+
- Node.js 18+
- Auth0 Account (free tier)

### Step 1: Auth0 Configuration (5 minutes)

1. **Create Auth0 Tenant**
   - Go to [auth0.com](https://auth0.com)
   - Create account and tenant: `mentoriq-dev`
   - Select region: US

2. **Configure Application**
   ```
   Applications > Create Application
   Name: MentorIQ Frontend
   Type: Single Page Application
   
   Settings:
   - Allowed Callback URLs: http://localhost:3000/api/auth/callback
   - Allowed Logout URLs: http://localhost:3000
   - Allowed Web Origins: http://localhost:3000
   ```

3. **Create API**
   ```
   APIs > Create API
   Name: MentorIQ API
   Identifier: https://api.mentoriq.com
   Signing Algorithm: RS256
   ```

4. **CRITICAL: Disable Public Signups**
   ```
   Tenant Settings > General > API Authorization Settings
   Default Directory: Username-Password-Authentication
   
   Authentication > Database > Username-Password-Authentication
   Settings > Disable Sign Ups: ON
   ```

### Step 2: Environment Setup (2 minutes)

1. **Copy environment files**
   ```bash
   cp backend/.env.template backend/.env
   cp frontend/.env.local.template frontend/.env.local
   ```

2. **Update Auth0 credentials**
   Edit `backend/.env`:
   ```
   AUTH0_DOMAIN=your-tenant.auth0.com
   AUTH0_API_AUDIENCE=https://api.mentoriq.com
   AUTH0_CLIENT_ID=your-frontend-client-id
   ```
   
   Edit `frontend/.env.local`:
   ```
   AUTH0_ISSUER_BASE_URL=https://your-tenant.auth0.com
   AUTH0_CLIENT_ID=your-frontend-client-id
   AUTH0_CLIENT_SECRET=your-frontend-client-secret
   ```

### Step 3: Start Development (1 minute)

```bash
# Option 1: Automated startup
./scripts/start-dev.sh

# Option 2: Manual startup
# Terminal 1 - Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Terminal 2 - Frontend  
cd frontend
npm install
npm run dev
```

### Step 4: Verify Setup

1. **Backend Health Check**: http://localhost:8000/health
2. **Frontend**: http://localhost:3000
3. **API Docs**: http://localhost:8000/docs
4. **Try Login**: Click "Sign In Securely"

### Step 5: Create Parent Test Account

1. Go to Auth0 Dashboard > User Management > Users
2. Create User:
   ```
   Email: testparent@example.com
   Password: TempPassword123!
   Connection: Username-Password-Authentication
   ```

3. **CRITICAL**: Add metadata
   ```json
   {
     "role": "parent",
     "verified": true
   }
   ```

## 🔒 Security Validation Checklist

- [ ] Auth0 public signups disabled
- [ ] Parent role required in JWT
- [ ] No child registration possible
- [ ] All PII encrypted before database
- [ ] COPPA notices visible
- [ ] Security headers present
- [ ] Rate limiting active

## 🚨 Common Issues

### "Auth0 service unavailable"
- Check Auth0 domain in environment files
- Verify tenant is active

### "Parent role required"  
- Add role metadata to test user in Auth0 dashboard

### "Encryption service unavailable"
- Check ENCRYPTION_KEY is set in backend/.env
- Key should be base64-encoded 256-bit

### Frontend won't start
- Run `npm install` in frontend directory
- Check Node.js version (18+)

### Backend import errors
- Activate virtual environment: `source venv/bin/activate`
- Install dependencies: `pip install -r requirements.txt`

## 📋 S-MVP Completion Checklist

### Hour 24 Goals:
- [ ] Parent can register (Auth0)
- [ ] Parent can login via frontend
- [ ] JWT validation working
- [ ] All PII encrypted
- [ ] COPPA compliance visible
- [ ] Security headers present

### Hour 48 Goals:
- [ ] Parent dashboard functional
- [ ] Child profile creation
- [ ] API endpoints secured
- [ ] Rate limiting active
- [ ] Audit logging operational
- [ ] Ready for staging deployment

## 🎯 Next Steps

After S-MVP validation:
1. Complete Milestone 0 remaining items
2. Add database integration (PostgreSQL)
3. Implement mentor verification
4. Build AI safety pipeline
5. Deploy to staging environment

## 🆘 Support

- **Security Issues**: Check security configuration first
- **Auth0 Issues**: Verify tenant settings and credentials  
- **General Issues**: Check logs in terminal output

**Emergency Contact**: If critical security issue found, stop development and escalate immediately.

---

**Remember**: This is a security-first S-MVP. Every component has been designed with COPPA compliance and parent control as the foundation.