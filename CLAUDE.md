# Claude.md - AI-Augmented Mentor Platform

## **Incremental Development Goals**

### **Current Phase Focus: Phase 1 - MVP Foundation**
Build core mentor management platform with hybrid SaaS + AI interface foundation. Establish authentication, basic mentor workflows, and split-screen UI architecture.

### **Phase Progression Strategy:**
```
Development Roadmap:
├── Phase 1: MVP Foundation (Weeks 1-4)
│   ├── Mentor authentication and profile management
│   ├── Basic program creation and student enrollment
│   ├── Split-screen UI layout (traditional SaaS + chat placeholder)
│   └── Data collection infrastructure for future AI
├── Phase 2: AI Chat Interface (Weeks 5-8)
│   ├── Conversational mentor query processing
│   ├── Dynamic dashboard generation from chat queries
│   ├── Integration between traditional forms and AI responses
│   └── Pattern-matched responses for common mentor questions
├── Phase 3: AI Landing Page (Weeks 9-12)
│   ├── Conversational program discovery for visitors
│   ├── AI-powered mentor and program matching
│   ├── Natural language onboarding flows
│   └── Integration with core mentor platform
├── Phase 4: Predictive Features (Months 4-6)
│   ├── Student success prediction and risk assessment
│   ├── Mentor performance optimization suggestions
│   ├── Automated resource and scheduling recommendations
│   └── Proactive insights and early warning systems
└── Phase 5: Scale & Expand (Months 6+)
    ├── Multi-domain education platform foundation
    ├── Advanced AI model training and deployment
    ├── Enterprise features and scaling infrastructure
    └── Broader education ecosystem integration
```

### **Current Session Objective:**
[To be updated at the start of each Claude session with specific task]

### **Phase 1 Success Criteria:**
- [ ] Mentor can register, login, and create complete profile
- [ ] Basic program creation and student enrollment workflows functional
- [ ] Split-screen interface working (traditional SaaS + chat placeholder)
- [ ] All user interactions logged for future AI training
- [ ] 75% mentor adoption in beta group, 60% time savings achieved

---

## **Meta AI Team Approach: 0 to 1 Development Strategy**

You are the Senior Engineer building a **hybrid SaaS + AI conversational interface** for FLL mentor management. This follows Meta's proven approach of iterative development with rapid user feedback loops.

---

## **Product Vision**

### **Core Concept**
Traditional SaaS mentor management platform **augmented** with a Claude-style conversational interface:
- **Left Side:** Standard SaaS pages (forms, dashboards, management interfaces)
- **Right Side:** AI chat interface that queries data, provides insights, and drives actions
- **Integration:** Seamless bridge between conversation and traditional interfaces

### **Strategic Principle**
Build familiar SaaS foundations while adding transformative AI capabilities that mentors discover organically.

---

## **Meta 0-to-1 Development Framework**

### **Phase 0: Foundation Sprint (Week 1-2)**
**Meta Principle:** Establish minimum viable infrastructure for rapid iteration

#### **Backend Foundation**
```
Core Services:
├── Authentication (simple JWT)
├── Basic Data Models (mentors, programs, students)
├── API Layer (REST endpoints)
└── Chat Interface Stub (placeholder responses)
```

#### **Frontend Foundation**
```
Hybrid Interface:
├── Left Panel: Basic SaaS skeleton (React)
├── Right Panel: Chat UI (conversation interface)
├── Layout Manager (responsive split-screen)
└── State Bridge (sync between panels)
```

#### **Success Criteria Week 2**
- [ ] Mentor can log in and see split-screen interface
- [ ] Basic SaaS forms work (add program, add student)
- [ ] Chat interface accepts messages and shows placeholder responses
- [ ] Data flows between traditional forms and chat queries

---

### **Phase 1: MVP with Smart Responses (Week 3-4)**
**Meta Principle:** Prove value hypothesis with minimal AI complexity

#### **Traditional SaaS Core**
**Essential Pages:**
- Mentor profile setup
- Program creation form
- Student enrollment form  
- Basic dashboard (program overview)
- Simple calendar/scheduling

#### **AI Interface MVP**
**Hardcoded Smart Responses for Core Queries:**
```javascript
Query Patterns:
"How many students in my program?" → Parse data, return count + chart
"Show me attendance trends" → Generate simple attendance visualization  
"Who hasn't paid fees?" → Query payment status, return list
"What's my next class?" → Check calendar, return schedule info
"Add student John, age 12" → Trigger student enrollment flow
```

#### **Technical Implementation**
- **Pattern Matching:** Simple keyword detection for common queries
- **Data Visualization:** Pre-built chart components triggered by specific questions
- **Action Routing:** Chat commands that navigate to specific SaaS pages
- **Context Bridge:** Chat interface can read current page state

#### **Success Criteria Week 4**
- [ ] 5-7 core mentor questions answered intelligently
- [ ] Chat can trigger actions in traditional SaaS pages
- [ ] Basic data visualizations generated from queries
- [ ] Mentor can complete full program setup using hybrid interface

---

### **Phase 2: User Feedback & Intelligence Expansion (Week 5-8)**
**Meta Principle:** Rapid iteration based on real mentor usage patterns

#### **User Testing Strategy**
**Beta Group:** 5-10 actual FLL mentors
**Testing Focus:**
- Which questions do mentors ask most frequently?
- What traditional SaaS flows are still preferred?
- Where does the AI interface add vs. detract value?
- What queries break the pattern matching system?

#### **Intelligence Enhancement**
**Based on User Feedback:**
- Expand pattern matching for discovered query types
- Add more sophisticated data analysis responses
- Implement conversational follow-up questions
- Create smart suggestions based on mentor context

#### **Integration Improvements**
- **Bidirectional sync:** Traditional pages update chat context
- **Smart navigation:** AI suggests relevant pages based on questions
- **Action confirmations:** Chat interface confirms traditional form submissions
- **Context memory:** Remember previous queries within session

#### **Success Criteria Week 8**
- [ ] 15+ common mentor queries handled intelligently
- [ ] >80% of beta mentors prefer hybrid interface for daily tasks
- [ ] Clear user behavior patterns identified for Phase 3
- [ ] Technical foundation ready for advanced AI integration

---

### **Phase 3: Advanced AI Integration (Week 9-12)**
**Meta Principle:** Scale intelligence based on proven user patterns

#### **LLM Integration**
**Replace Pattern Matching with Real AI:**
- Fine-tuned model for mentor domain knowledge
- RAG (Retrieval Augmented Generation) with program data
- Natural language understanding for complex queries
- Dynamic response generation vs. template responses

#### **Predictive Capabilities**
**Proactive Intelligence:**
- "I notice Sarah's attendance is dropping - would you like to reach out?"
- "Based on similar programs, you might want to order more servo motors"
- "Your current pacing suggests moving the robot challenge to next week"

#### **Advanced Visualizations**
**Dynamic Chart Generation:**
- AI creates custom visualizations based on query intent
- Interactive charts with drill-down capabilities
- Export and sharing functionality for AI-generated insights

#### **Success Criteria Week 12**
- [ ] Natural language queries work reliably (not just pattern matching)
- [ ] AI provides proactive insights mentors find valuable
- [ ] Seamless integration between conversation and traditional workflows
- [ ] Platform ready for public beta launch

---

## **Facebook Engineering Best Practices**

### **Frontend: React Best Practices**

#### **Component Architecture**
```typescript
// Facebook's Component Standards
src/
├── components/
│   ├── shared/          // Reusable UI components
│   ├── mentor/          // Domain-specific components
│   └── __tests__/       // Co-located component tests
├── hooks/               // Custom React hooks
├── utils/               // Pure utility functions
├── types/               // TypeScript type definitions
└── __generated__/       // Auto-generated files (GraphQL, etc.)
```

#### **React Development Standards**
- **Hooks-First:** Functional components with custom hooks for logic
- **TypeScript:** Full type safety with strict compiler settings
- **CSS-in-JS:** Styled-components or Emotion for component styling
- **Performance:** React.memo, useMemo, useCallback for optimization
- **Testing:** Jest + React Testing Library for comprehensive coverage

#### **State Management**
```typescript
// Facebook's Recoil/Zustand Pattern
const useAppState = () => ({
  // Global state management
  // Atomic state updates
  // Optimistic updates for real-time feel
});
```

### **Backend: Node.js Microservices Standards**

#### **Service Architecture**
```
Facebook Microservices Pattern:
├── src/
│   ├── controllers/     // Request handlers
│   ├── services/        // Business logic
│   ├── models/          // Data models
│   ├── middleware/      // Express middleware
│   ├── utils/           // Utility functions
│   ├── types/           // TypeScript interfaces
│   └── __tests__/       // Service tests
├── docs/                // API documentation
├── scripts/             // Deployment scripts
└── Dockerfile          // Container configuration
```

#### **API Design Standards**
- **GraphQL-First:** Single endpoint with flexible queries
- **RESTful Fallbacks:** Traditional endpoints where GraphQL doesn't fit
- **API Versioning:** Backward compatibility with deprecation strategy
- **Rate Limiting:** Protect against abuse and ensure fair usage
- **Comprehensive Logging:** Structured logs for debugging and analytics

#### **Database Standards**
```sql
-- Facebook's Database Patterns
-- Optimized for read-heavy workloads
-- Denormalization for performance
-- Indexing strategy for query patterns
-- Connection pooling and caching layers
```

---

## **Open Source Technology Stack (AI-First with Python Backend)**

### **Backend Stack (Python)**
```
Core Technologies:
├── Python 3.11+ (latest stable)
├── FastAPI (modern async web framework)
├── PostgreSQL + SQLAlchemy (robust ORM)
├── Redis (caching and session management)
├── Pydantic (data validation and serialization)
├── JWT (python-jose library for authentication)
└── pytest (comprehensive testing framework)
```

### **AI/ML Stack (Python Native)**
```
AI Technologies:
├── transformers (Hugging Face LLM integration)
├── langchain (LLM application framework)
├── openai + anthropic (API clients)
├── pandas + numpy (data processing)
├── matplotlib + plotly (data visualizations)
├── scikit-learn (classical ML algorithms)
└── uvicorn (ASGI production server)
```

### **Frontend Stack (Unchanged)**
```typescript
Core Technologies:
├── React 18 (Facebook's open source)
├── TypeScript (Microsoft open source)
├── Vite (fast build tool)
├── TailwindCSS (utility-first CSS)
├── React Query (data fetching)
└── Zustand (state management)
```

### **Development Tools (All Free)**
```
Development Environment:
├── VS Code (Microsoft open source)
├── Python: black + flake8 + isort (code formatting)
├── Frontend: ESLint + Prettier
├── pytest + Jest + Testing Library (comprehensive testing)
├── GitHub Actions (free CI/CD)
├── Docker + Docker Compose (containerization)
└── Vercel (frontend) + Render/Railway (Python backend hosting)
```

### **Why Python Backend for AI Platform**

#### **AI-First Architecture Benefits**
- **Native AI Integration:** Direct use of transformers, langchain libraries without external API complexity
- **Superior Data Processing:** Leverage pandas, numpy for mentor behavioral analytics
- **Dynamic Visualizations:** Use plotly for AI-generated charts and insights
- **Facebook Alignment:** Most Facebook AI tools are Python-based (PyTorch ecosystem)

#### **Performance and Development Benefits**
- **FastAPI Performance:** Matches Node.js/Express speed for web APIs
- **Type Safety:** Pydantic provides validation similar to TypeScript
- **Async Support:** Native async/await for concurrent request handling
- **Documentation:** Auto-generated OpenAPI documentation
- **Testing:** Comprehensive pytest framework

---

## **Development Boundaries & Change Management**

### **Critical: Claude Development Constraints**

#### **STRICT BOUNDARIES - Never Change Without Explicit Request**
```
Protected Areas (DO NOT MODIFY unless specifically asked):
├── Package.json/requirements.txt dependencies
├── Database schema once established
├── API endpoint contracts
├── Authentication flow
├── File/folder structure once created
├── Environment configuration
└── Any existing working code
```

#### **Mandatory Change Protocol**
```
Before making ANY change, Claude must:
1. Clearly state what will be modified (exact files and functions)
2. Explain why the change is necessary
3. List potential breaking effects
4. Show the exact diff of proposed changes
5. Wait for explicit approval
6. Provide rollback instructions

After making approved changes:
1. Test the specific change
2. Verify existing functionality still works
3. Log all changes made in detail
4. Provide git commit command with descriptive message
5. Confirm change is ready for commit before proceeding
```

#### **Scope Limitation Rules**
```
Change Scope Control:
├── Make ONLY the requested change
├── Do NOT optimize or refactor unrelated code
├── Do NOT add features not specifically requested
├── Do NOT modify imports/dependencies unless required
├── Do NOT change coding style of existing code
└── Do NOT add "helpful" improvements beyond scope
```

#### **Logging and Documentation Requirements**
```
For Every Change, Claude Must Provide:

1. PRE-CHANGE LOG:
   - Current state description
   - Exact files to be modified
   - Specific lines/functions affected
   - Expected outcome

2. CHANGE IMPLEMENTATION:
   - Show exact code changes (diff format)
   - Explain each modification
   - Highlight any dependencies

3. POST-CHANGE LOG:
   - Summary of what was changed
   - Testing instructions
   - Git commit message
   - Verification checklist

4. COMMIT PROTOCOL:
   - Provide exact git commands
   - Descriptive commit message following format:
     "feat(component): brief description of change"
   - Confirm change is complete and tested
```

#### **Approved Change Types (No Permission Needed)**
```
Safe Changes:
├── Adding new functions (not modifying existing)
├── Adding new components (not changing existing)
├── Adding new API endpoints (not changing existing)
├── Adding comments and documentation
├── Adding tests for existing code
├── Bug fixes that don't change interfaces (with approval)
└── Adding new files (not modifying existing)
```

### **Git-Based State Management Protocol**

#### **Before Every Development Session**
```
Required State Verification:
1. Current git status (clean working directory)
2. Last commit hash and message
3. Current branch name
4. Any uncommitted changes
5. Specific task to accomplish this session
```

#### **During Development**
```
Incremental Development Rules:
1. Start with exact current state (git status)
2. Make ONE small change at a time
3. Test change immediately after implementation
4. Document change in detail
5. Provide commit command before next change
6. Confirm commit success before proceeding
```

#### **Git Command Protocol**
```
For Every Change, Provide These Commands:

# Check current state
git status
git log --oneline -5

# Stage and commit changes
git add [specific files changed]
git commit -m "type(scope): description

- Specific change 1
- Specific change 2
- Any breaking changes noted"

# Verify commit
git log --oneline -1
git status
```

#### **Change Documentation Template**
```
Change Log Entry:

## CHANGE REQUEST: [Brief description]

### PRE-CHANGE STATE:
- Files affected: [list]
- Current functionality: [description]
- Git commit: [hash and message]

### IMPLEMENTATION:
```diff
[Show exact code changes in diff format]
```

### POST-CHANGE STATE:
- New functionality: [description]
- Files modified: [list]
- Testing required: [steps]

### GIT COMMIT:
```bash
git add [files]
git commit -m "[commit message]"
```

### VERIFICATION:
- [ ] Change implements only requested functionality
- [ ] Existing functionality unchanged
- [ ] Code follows project patterns
- [ ] Ready for commit
```

### **Emergency Stop Conditions**

#### **Claude Must STOP Immediately If:**
```
Stop Conditions:
├── Any existing test starts failing
├── Application won't start/build
├── Database connection issues
├── Authentication flow breaks
├── API endpoints return errors
├── Frontend components crash
└── Any breaking change to existing functionality
```

#### **Recovery Protocol**
```
When Issues Occur:
1. STOP all development immediately
2. Document exact error/issue
3. Identify last working state
4. Provide rollback commands:
   git reset --hard [last-working-commit]
5. Request new approach before continuing
6. Do NOT attempt fixes without explicit approval
```

### **Technology Constraints**

#### **Dependency Management**
```
Package Installation Rules:
├── Only add dependencies when explicitly requested
├── Stick to specified tech stack
├── No framework changes mid-development
├── No experimental or beta packages
└── Document all dependency additions
```

#### **Architecture Boundaries**
```
Fixed Architecture Elements:
├── React + TypeScript frontend
├── Node.js + Express backend
├── PostgreSQL database
├── Split-screen UI layout
└── RESTful API design (no GraphQL unless requested)
```

---

## **Specific Technology Choices (Open Source)**

### **Frontend: React + TypeScript (Unchanged)**
```
Technologies:
├── React 18 with Hooks
├── TypeScript for type safety
├── Vite for fast development
├── TailwindCSS for styling
├── React Query for API calls
└── Zustand for state management
```

### **Backend: Python + FastAPI**
```
Technologies:
├── FastAPI async web framework
├── SQLAlchemy ORM for database
├── Pydantic for data validation
├── python-jose for JWT authentication
├── structlog for JSON logging
└── redis-py for caching
```

### **AI/ML: Native Python Integration**
```
Technologies:
├── transformers for LLM integration
├── langchain for AI application framework
├── pandas for data processing
├── plotly for dynamic visualizations
├── scikit-learn for ML models
└── openai + anthropic for API integration
```

### **Database: PostgreSQL**
```sql
-- PostgreSQL as primary database
-- Redis for caching and sessions
-- SQLAlchemy for database management
-- Alembic for migrations
-- Connection pooling
```

### **Development Environment**
```
Local Development Setup:
├── Docker Compose for services
├── GitHub for version control
├── VS Code with Python + TypeScript extensions
├── black + flake8 for Python code quality
└── ESLint + Prettier for TypeScript code quality
```

---

## **Communication Protocol with Claude**

### **Before Each Development Session**
```
Required Context Sharing:
1. Current git status and last commit
2. What specific feature to add
3. Any files that are off-limits for modification
4. Expected outcome and success criteria
5. Rollback plan if changes break anything
```

### **During Development**
```
Claude Must:
├── Announce what file/function will be modified
├── Show exact changes before implementing
├── Explain reasoning for each change
├── Provide testing instructions
└── Confirm changes work before proceeding
```

### **After Each Change**
```
Validation Protocol:
1. Test the specific change
2. Verify existing functionality still works
3. Commit if successful
4. Rollback if anything breaks
5. Document the change and its impact
```

---

## **Tech Stack Justification (Open Source)**

### **Why These Specific Tools**

#### **React + TypeScript**
- Facebook's proven patterns for large applications
- Strong typing prevents runtime errors
- Excellent tooling and community support
- Easy testing and debugging

#### **Python + FastAPI Benefits**
- **Performance:** FastAPI matches Node.js/Express performance for web APIs
- **Type Safety:** Pydantic provides validation similar to TypeScript for Python
- **Async Support:** Native async/await for concurrent request handling
- **AI Integration:** Seamless integration with transformers, langchain, and other ML libraries
- **Documentation:** Auto-generated OpenAPI documentation
- **Testing:** pytest provides comprehensive testing capabilities

#### **AI-First Development Advantages**
- **Direct LLM Integration:** Use transformers and langchain without external API complexity
- **Native Data Processing:** Leverage pandas and numpy for mentor behavioral analytics
- **Dynamic Visualizations:** Generate charts and insights using plotly
- **Facebook Ecosystem:** Aligns with Facebook's Python-based AI infrastructure

---

## **Rollback and Recovery Strategy**

### **Git Safety Net**
```bash
# Before any significant change
git add .
git commit -m "Working state before [change description]"

# If change breaks anything
git reset --hard HEAD~1  # Instant rollback
```

### **Development Safety Checks**
```
Before Every Change:
├── Is current state working and committed?
├── Is this change absolutely necessary?
├── Can this be added without modifying existing code?
├── Do I have a clear rollback plan?
└── Has this been explicitly requested?
```

### **Emergency Procedures**
```
If Development Goes Wrong:
1. Stop immediately
2. Assess what broke
3. Rollback to last working commit
4. Document what went wrong
5. Request new approach before proceeding
```

This framework ensures stable, incremental development with clear boundaries and prevents Claude from making unauthorized changes that could break the working system.

---

## **Code Quality & Documentation Standards**

### **Documentation Requirements**

#### **API Documentation**
```typescript
/**
 * Facebook JSDoc Standards
 * @description Clear, comprehensive function documentation
 * @param {string} mentorId - Unique identifier for mentor
 * @returns {Promise<MentorProfile>} Mentor profile data
 * @throws {ValidationError} When mentorId is invalid
 * @example
 * const profile = await getMentorProfile('mentor_123');
 */
```

#### **README Standards**
```markdown
# Facebook README Template
## Quick Start (< 5 minutes to run locally)
## Architecture Overview (with diagrams)
## API Documentation (links to detailed docs)
## Contributing Guidelines (code standards)
## Deployment Guide (step-by-step)
```

#### **Code Comments**
- **Why, not What:** Explain business logic, not syntax
- **Decision Context:** Document architectural choices
- **TODO/FIXME:** Link to tickets for future improvements
- **Performance Notes:** Document optimization decisions

### **Testing Strategy**

#### **Facebook Testing Pyramid**
```
Testing Levels:
├── Unit Tests (70%): Individual function testing
├── Integration Tests (20%): Service interaction testing
├── E2E Tests (10%): Full user workflow testing
└── Manual Testing: Edge cases and UX validation
```

#### **Test Standards**
- **Coverage Requirements:** 80% minimum, 90% for critical paths
- **Test Co-location:** Tests next to the code they test
- **Mocking Strategy:** Mock external dependencies, test business logic
- **Performance Testing:** Load testing for expected user volumes

### **Security Best Practices**

#### **Application Security**
- **Input Validation:** Sanitize all user inputs
- **Authentication:** JWT with proper expiration and refresh
- **Authorization:** Role-based access control (RBAC)
- **HTTPS Everywhere:** TLS 1.3 for all communications
- **Security Headers:** CSP, HSTS, X-Frame-Options

#### **Data Protection**
- **Encryption:** At rest and in transit
- **PII Handling:** COPPA/FERPA compliance for student data
- **Audit Logging:** Track all data access and modifications
- **Regular Scans:** Dependency vulnerability checks

---

## **Development Workflow Standards**

### **Git Workflow**
```
Facebook Git Standards:
├── main (always deployable)
├── feature/TASK-123-description
├── hotfix/critical-bug-fix
└── release/v1.2.3
```

#### **Commit Standards**
```bash
# Facebook Commit Message Format
feat(auth): add JWT refresh token rotation

- Implement automatic token refresh
- Add refresh endpoint with rate limiting
- Update client to handle token rotation
- Closes TASK-123
```

#### **Pull Request Requirements**
- **Code Review:** Minimum 2 reviewers for production code
- **CI Passing:** All tests and linting must pass
- **Documentation:** Update docs for API or architecture changes
- **Security Review:** Security team review for auth/data changes

### **Code Review Standards**

#### **Review Checklist**
- [ ] Code follows established patterns and conventions
- [ ] Security considerations addressed
- [ ] Performance implications considered
- [ ] Tests cover new functionality
- [ ] Documentation updated
- [ ] Error handling implemented
- [ ] Logging added for debugging

#### **Review Culture**
- **Constructive Feedback:** Focus on code, not coder
- **Knowledge Sharing:** Explain reasoning behind suggestions
- **Quick Turnaround:** Review within 24 hours
- **Nitpick Labeling:** Distinguish between critical and style issues

---

## **Technical Architecture with Facebook Standards**

### **Frontend Structure (Facebook React Standards)**
```typescript
src/
├── components/
│   ├── shared/
│   │   ├── Button/
│   │   │   ├── Button.tsx
│   │   │   ├── Button.test.tsx
│   │   │   ├── Button.stories.tsx
│   │   │   └── index.ts
│   │   └── Layout/
│   ├── mentor/
│   │   ├── MentorDashboard/
│   │   ├── StudentList/
│   │   └── ChatInterface/
│   └── __tests__/
├── hooks/
│   ├── useAuth.ts
│   ├── useMentorData.ts
│   └── useChat.ts
├── services/
│   ├── api.ts
│   ├── auth.ts
│   └── chat.ts
├── utils/
│   ├── formatters.ts
│   ├── validators.ts
│   └── constants.ts
└── types/
    ├── api.ts
    ├── mentor.ts
    └── student.ts
```

### **Backend Services (Python + FastAPI Pattern)**
```python
Services Architecture:
├── auth-service/
│   ├── app/
│   │   ├── api/
│   │   │   ├── auth.py          # FastAPI route handlers
│   │   │   └── dependencies.py  # Auth dependencies
│   │   ├── core/
│   │   │   ├── security.py      # JWT utilities
│   │   │   └── config.py        # Environment settings
│   │   ├── models/
│   │   │   └── user.py          # SQLAlchemy models
│   │   ├── schemas/
│   │   │   └── user.py          # Pydantic schemas
│   │   └── services/
│   │       └── auth_service.py  # Business logic
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
├── mentor-service/
├── chat-service/
└── analytics-service/
```

### **AI Integration Architecture**
```python
AI Pipeline Services:
├── chat-service/
│   ├── app/
│   │   ├── ai/
│   │   │   ├── query_processor.py    # NLP intent recognition
│   │   │   ├── response_generator.py # LLM response creation
│   │   │   └── data_synthesizer.py   # Combine multiple data sources
│   │   ├── models/
│   │   │   └── conversation.py       # Chat history models
│   │   └── services/
│   │       ├── mentor_ai.py          # Domain-specific AI logic
│   │       └── visualization.py     # Dynamic chart generation
└── analytics-service/
    ├── app/
    │   ├── ml/
    │   │   ├── prediction_models.py  # Student success prediction
    │   │   └── insight_generator.py  # Proactive insights
    │   └── data/
    │       └── behavioral_analytics.py # Mentor behavior analysis
```

---

## **Meta-Style Development Principles**

### **1. Move Fast, Don't Break Things**
- Each week builds incrementally on previous week
- Maintain working SaaS functionality throughout
- AI features enhance rather than replace proven workflows

### **2. User-Centric Iteration**
- Real mentor feedback drives every development decision
- Weekly user testing with actual FLL mentors
- Quantitative metrics + qualitative insights guide priorities

### **3. Technical Excellence**
- Clean API design supporting both traditional and AI interfaces
- Scalable architecture ready for Meta-scale growth
- Performance standards: <2s response time for all interactions

### **4. Data-Driven Intelligence**
- Every user interaction captured for AI improvement
- A/B testing for AI response effectiveness
- Continuous learning loops improving assistant capabilities

---

## **Success Metrics by Phase**

### **Phase 0 (Week 2): Foundation**
- Technical infrastructure operational
- Basic mentor workflows functional
- Split-screen interface working

### **Phase 1 (Week 4): MVP Value**
- 5+ core mentor questions answered intelligently
- Hybrid interface completes essential mentor tasks
- Clear value demonstration for AI augmentation

### **Phase 2 (Week 8): User Validation**
- >80% mentor preference for hybrid vs. traditional interface
- 15+ query types handled effectively
- Strong user engagement and retention signals

### **Phase 3 (Week 12): AI Platform**
- Natural language query processing reliable
- Proactive AI insights valued by mentors
- Platform ready for broader beta launch

---

## **Risk Mitigation**

### **Technical Risks**
- **AI Complexity:** Start with pattern matching, evolve to LLM
- **Performance:** Optimize for mobile mentor usage patterns
- **Integration Complexity:** Maintain clear separation between SaaS and AI systems

### **Product Risks**
- **User Adoption:** Keep traditional workflows as fallback options
- **Value Demonstration:** Focus on clear mentor time savings
- **Scope Creep:** Resist adding features not validated by user testing

---

## **Key Deliverables**

### **Week 2: Technical Foundation**
- Split-screen interface with working authentication
- Basic SaaS forms and AI chat placeholder
- Data flow between traditional and conversational interfaces

### **Week 4: Functional MVP**
- Complete mentor workflow through hybrid interface
- Pattern-matched responses for common queries
- Demonstrated value of AI augmentation approach

### **Week 8: User-Validated Product**
- Beta mentor feedback integrated
- Expanded AI capabilities based on real usage
- Clear roadmap for advanced AI features

### **Week 12: Scalable AI Platform**
- Production-ready AI integration
- Proven mentor engagement and value
- Technical foundation for rapid feature expansion

---

This approach follows Meta's proven strategy of building minimal viable functionality quickly, getting user feedback fast, and iterating based on real usage patterns rather than assumptions.