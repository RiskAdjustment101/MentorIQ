# MentorIQ - AI-Powered FLL Mentoring Platform

## Overview
MentorIQ is a revolutionary parent-controlled, AI-powered mentoring platform for FIRST Lego League (FLL) teams. Built with a focus on youth safety, COPPA compliance, and educational excellence, the platform connects qualified mentors with FLL teams while giving parents complete control over their children's experience.

## Key Features

### Parent-First Architecture
- **Zero child accounts** - All profiles managed by parents
- **Complete data ownership** - Parents control all child information
- **Transparent AI decisions** - Every recommendation explained clearly
- **Real-time monitoring** - Full visibility into mentoring sessions

### AI-Powered Intelligence
- **Constitutional AI** throughout - Helpful, harmless, honest interactions
- **Smart mentor matching** - AI analyzes compatibility and safety
- **Dynamic personalization** - Adaptive content for each user type
- **Safety monitoring** - Automatic detection of concerning content

### Technical Excellence
- **COPPA compliant** by design - No child data collection
- **Field-level encryption** - All PII protected
- **Audit logging** - Complete accountability without storing PII
- **Zero-cost infrastructure** - Built entirely on open-source and free tiers

## Tech Stack

### Backend
- **FastAPI** - High-performance Python web framework
- **PostgreSQL** - Primary database with SQLAlchemy 2.0
- **Redis** - Caching and session management
- **JWT Auth** - Secure authentication with role-based access

### Frontend
- **React 18** - Modern component architecture
- **TypeScript** - Type-safe development
- **Tailwind CSS** - Utility-first styling
- **React Query** - Efficient API state management

### AI & Security
- **Claude API** - Primary AI reasoning engine
- **OpenAI API** - Backup AI services
- **Field encryption** - cryptography library for PII protection
- **Rate limiting** - DDoS protection and API safety

## Project Structure
```
MentorIQ/
├── backend/            # FastAPI application
│   ├── app/           # Main application code
│   ├── api/           # API endpoints
│   ├── models/        # SQLAlchemy models
│   ├── schemas/       # Pydantic schemas
│   ├── services/      # Business logic
│   └── utils/         # Utility functions
├── frontend/          # React application
│   ├── src/          # Source code
│   └── public/       # Static assets
├── tests/            # Test suites
│   ├── backend/      # Backend tests
│   └── frontend/     # Frontend tests
├── docs/             # Documentation
└── CLAUDE.md         # AI development guide
```

## Development Timeline

### Week 1: Foundation
- FastAPI + PostgreSQL setup
- Parent authentication system
- Basic AI integration framework
- Deploy to free hosting

### Week 2: Core Features
- Parent onboarding flow
- Child profile management
- Mentor matching algorithm
- Safety monitoring system

### Week 3: AI Integration
- Full Claude API integration
- Safety validation pipeline
- Parent dashboard
- Mentor guidance tools

### Week 4: Launch
- Security testing
- COPPA compliance review
- Performance optimization
- Beta launch

## Getting Started

### Prerequisites
- Python 3.11+
- Node.js 18+
- PostgreSQL 14+
- Redis 6+

### Quick Start
```bash
# Clone repository
git clone https://github.com/RiskAdjustment101/MentorIQ.git
cd MentorIQ

# Backend setup
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend setup (new terminal)
cd frontend
npm install
npm run dev
```

## Security & Compliance

### COPPA Compliance
- No direct child registration
- Parental consent for all actions
- Right to deletion implemented
- Data portability available

### Data Protection
- All PII encrypted at rest
- TLS for data in transit
- Audit logs without PII
- Regular security scans

## Contributing
Please see [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## License
[License details to be added]

## Support
For security issues, please email: [security contact to be added]

---

**Built with Constitutional AI principles: Helpful, Harmless, Honest**