# Claude.md - FLL Mentor Platform Development Guide

## Project Overview
Building a secure, AI-first mentoring platform for FIRST Lego League teams with **$0 engineering budget** using Claude AI and open-source tools. **Parent-managed profiles ensure COPPA compliance while AI guides every interaction.**

**Tech Stack**: Python + FastAPI + PostgreSQL + Next.js + Tailwind CSS

## Core Philosophy: Parent-First + AI-Enabled

### Revolutionary Approach
- **Parents own ALL data** - Complete control over child profiles
- **AI guides everything** - From landing page to mentor matching to session management
- **Zero child accounts** - Everything managed through parent oversight
- **Constitutional AI** - Helpful, harmless, honest in every interaction

## Claude Prompting Framework (Anthropic Best Practices)

### Essential Context Template
```
SYSTEM CONTEXT:
- Project: FLL Mentor Platform (youth safety critical)
- Backend: Python 3.11+ + FastAPI + SQLAlchemy 2.0 + PostgreSQL
- Frontend: Next.js 14+ + TypeScript + Tailwind CSS
- Constraints: $0 budget, open source only, 4-week delivery
- Users: Parents (owners), Children (supervised), Mentors (verified)

SAFETY CONTEXT:
- COPPA compliance mandatory - parents control all child data
- Constitutional AI required - helpful, harmless, honest
- Never store child PII in logs, always encrypt sensitive fields
- All AI decisions must be explainable to parents

TASK: [Specific feature/component/endpoint]
INPUT: [What data comes in]
OUTPUT: [What should be returned]
SECURITY: [Specific safety requirements]
```

### FastAPI Endpoint Prompt Template
```
Create a FastAPI endpoint: [HTTP method] [path]

REQUIREMENTS:
- Pydantic v2 models with validators
- SQLAlchemy 2.0 async queries
- JWT authentication with role checking
- Rate limiting: [specify limits]
- Parent permission validation
- Audit logging (no PII)
- Error handling with proper HTTP codes

DELIVERABLES:
1. FastAPI route handler
2. Pydantic request/response models  
3. SQLAlchemy database operations
4. Pytest test cases
5. OpenAPI documentation

Focus on security, parent oversight, and Constitutional AI principles.
```

### AI Feature Prompt Template
```
Build AI-powered [feature name] following Constitutional AI:

HELPFUL: [How this genuinely improves parent/child experience]
HARMLESS: [Youth safety protections required]
HONEST: [Limitations and when human oversight needed]

TECHNICAL:
- Claude API integration with retry logic
- Input validation and sanitization
- Safety content filtering
- Fallback when AI unavailable
- Parent-friendly explanations

PARENT CONTROL:
- Parents see all AI recommendations
- Parents approve all AI decisions
- AI explains reasoning clearly
- Emergency override capabilities
```

## Technology Stack (Open Source Only)

### Backend (Python + FastAPI)
- **FastAPI** - High-performance async web framework
- **SQLAlchemy 2.0** - Async ORM with PostgreSQL
- **Pydantic v2** - Data validation and serialization
- **FastAPI-Users** - Authentication and user management
- **Celery + Redis** - Background task processing
- **pytest** - Testing framework

### Frontend (Next.js + TypeScript)
- **Next.js 14** - Full-stack React framework with SSR/SSG
- **Tailwind CSS** - Styling (Anthropic design system)
- **React Hook Form** - Form validation
- **TanStack Query** - API state management
- **Next Auth** - Authentication integration

### Infrastructure & Security
- **PostgreSQL** - Primary database
- **Redis** - Caching and session storage
- **Docker** - Containerization
- **Railway/Render** - Free hosting
- **python-jose** - JWT handling
- **cryptography** - Data encryption

### AI & Communication
- **Anthropic Claude API** - Core AI reasoning
- **OpenAI API** - Backup AI services
- **Twilio** - Parent SMS notifications

## Security-First Development Process

### 1. Parent Permission Validation
Every endpoint must verify:
```python
# Template for all endpoints
async def verify_parent_permission(parent_id: int, child_id: int):
    # Verify parent owns child profile
    # Log access attempt
    # Validate consent status
```

### 2. AI Safety Validation
All AI responses must pass:
```python
# Template for AI safety checking
async def validate_ai_response(content: str) -> bool:
    # Pattern-based safety checks
    # Constitutional AI validation
    # Parent-appropriate language check
    # Age-appropriate content verification
```

### 3. COPPA Compliance Checklist
- [ ] No child accounts - parents create everything
- [ ] Parental consent tracked with timestamps
- [ ] PII encrypted with field-level encryption
- [ ] Audit trails for all data access
- [ ] Data export available to parents
- [ ] Right to deletion implemented

## AI-Powered Features Architecture

### Landing Page Personalization
- **AI detects visitor type** (concerned parent, busy parent, mentor)
- **Dynamic content adaptation** based on visitor behavior
- **Contextual AI chatbot** answering specific concerns
- **Trust-building messaging** emphasizing parent control

### Parent Onboarding Assistant
- **AI guides profile creation** with smart suggestions
- **Real-time validation** of parent inputs
- **Safety preference setup** with AI explanations
- **Goal setting assistance** for mentoring outcomes

### Intelligent Mentor Matching
- **AI analyzes compatibility** between mentor skills and child needs
- **Parent preference weighting** in matching algorithm
- **Explainable matches** with clear reasoning for parents
- **Safety scoring** based on background checks and history

### Session Management & Monitoring
- **Real-time AI guidance** for mentors during sessions
- **Automatic safety monitoring** of all communications
- **Parent notifications** for important events or concerns
- **Progress tracking** with AI-generated insights

## Development Workflow

### Week 1: Foundation
- Set up FastAPI + PostgreSQL + Next.js
- Implement parent-only authentication
- Create basic AI prompt framework
- Deploy to free hosting tier (Vercel for frontend)

### Week 2: Core Features
- Parent onboarding with AI assistance
- Child profile creation (parent-managed)
- Basic mentor matching algorithm
- Safety monitoring system

### Week 3: AI Integration
- Claude API integration for all features
- AI safety validation pipeline
- Parent dashboard with AI insights
- Mentor guidance system

### Week 4: Polish & Launch
- Security testing and COPPA compliance review
- Parent usability testing
- Performance optimization
- Beta launch with limited users

## Success Metrics

### Technical Excellence
- Zero security vulnerabilities in production
- <2 second API response times
- 99.9% uptime
- 100% COPPA compliance

### Parent Satisfaction
- 90%+ parent approval of AI recommendations
- 95%+ feel in control of child's experience
- 80%+ would recommend to other parents
- <24 hour response to safety concerns

### Learning Outcomes
- 85%+ of matched mentoring relationships complete full season
- Measurable improvement in FLL team performance
- 75%+ of students continue in STEM after program
- Positive feedback from mentors on student engagement

## Budget: $80/month Maximum
- OpenAI + Claude APIs: ~$50/month
- Hosting (Railway/Render): $0 (free tier)
- Database (Supabase): $0 (free tier)
- All other tools: $0 (open source)

## Emergency Contacts & Support
- **Security Issues**: Immediate parent notification + platform lockdown
- **AI Safety Concerns**: Human review within 2 hours
- **COPPA Violations**: Legal counsel engagement + corrective action
- **System Outages**: Status page + parent communication

## Getting Started Checklist

### Initial Setup (Day 1)
- [ ] Clone repository template
- [ ] Set up FastAPI + PostgreSQL locally
- [ ] Configure Claude API access
- [ ] Implement basic parent authentication
- [ ] Create first AI-powered feature

### Security Configuration (Day 2)
- [ ] Set up encryption for all PII fields
- [ ] Implement audit logging
- [ ] Configure rate limiting
- [ ] Set up automated security scanning
- [ ] Test COPPA compliance features

### AI Integration (Day 3-7)
- [ ] Build Constitutional AI prompt framework
- [ ] Implement safety validation pipeline
- [ ] Create parent-friendly AI explanations
- [ ] Test fallback mechanisms
- [ ] Deploy to staging environment

### Launch Preparation (Day 8-14)
- [ ] Parent usability testing
- [ ] Security penetration testing
- [ ] Legal compliance review
- [ ] Performance optimization
- [ ] Beta launch with 10 families

---

**Bottom Line**: This guide provides the framework to build a revolutionary parent-controlled, AI-powered mentoring platform that genuinely improves STEM education while maintaining the highest safety standards - all within a $0 engineering budget and 4-week timeline.