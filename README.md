# MentorIQ - AI-Augmented Mentor Platform

**Transforming FIRST LEGO League mentoring through conversational AI and intelligent program management.**

MentorIQ is building the future of educational mentoring by combining traditional SaaS mentor management with conversational AI interfaces. This repository contains **Phase 1: AI-First Landing Page** - the first component of our comprehensive platform.

## 🎯 Platform Vision

**Core Mission**: Enable mentors to save 60%+ of their administrative time while improving student outcomes through AI-powered insights and automation.

**Strategic Approach**: Hybrid SaaS + AI interface where traditional mentor workflows are augmented with conversational intelligence, following Meta's proven 0-to-1 development methodology.

## 🗺️ Development Roadmap

### **Phase 1: AI-First Landing Page** ✅ *Completed*
Transform traditional program discovery into conversational AI experience
- **70/30 Split-screen Layout**: Content-first with AI assistant sidebar
- **Smart Program Discovery**: Natural language queries for parents, mentors, students
- **Anthropic Design System**: Professional dark theme with orange accents
- **Fully Responsive**: Desktop, tablet, and mobile optimized

### **Phase 1.5: Bidirectional Registration System** ✅ *Current Implementation*
Revolutionary registration experience with dual interaction modes
- **Bidirectional Sync**: Real-time synchronization between form and AI chat
- **Smart Field Detection**: AI extracts names, emails, user types from conversation
- **Contextual Responses**: Domain-aware AI with role-specific messaging
- **Progressive Registration**: Guided experience with completion tracking

### **Phase 2: Core Mentor Platform** 🚧 *Next: Weeks 5-8*
Traditional SaaS functionality augmented with AI chat interface
- Mentor authentication and profile management
- Program creation and student enrollment workflows
- Split-screen UI (traditional forms + AI chat assistant)
- Real-time dashboard generation from conversational queries

### **Phase 3: Predictive AI Features** 📋 *Future: Months 4-6*
Advanced intelligence for mentor optimization
- Student success prediction and risk assessment
- Automated resource and scheduling recommendations
- Mentor performance optimization suggestions
- Proactive insights and early warning systems

### **Phase 4: Multi-Domain Platform** 🌟 *Vision: Months 6+*
Scalable foundation for broader education ecosystem
- Advanced AI model training and deployment
- Enterprise features and scaling infrastructure
- Integration with other educational programs beyond FLL

## 🔧 Current Implementation (Phase 1 + 1.5)

### **AI-Enhanced Landing Page Features**
- **Conversational Program Discovery**: Natural language queries for finding FLL programs
- **Smart Recommendations**: Dynamic program matching with detailed mentor profiles
- **Multi-User Flows**: Tailored experiences for parents, mentors, and students
- **Professional Design**: Anthropic-style interface with dark theme and orange accents

### **Bidirectional Registration System Features**
- **Dual Interface Registration**: Complete signup via traditional form OR conversational AI
- **Real-time Synchronization**: Form inputs trigger AI responses, AI responses populate form
- **Intelligent Field Extraction**: AI parses natural language for names, emails, user types
- **Contextual Intelligence**: Domain-aware responses (.edu, .com) and role-specific messaging
- **Progressive Experience**: Guided registration with visual progress tracking
- **Performance Optimized**: 177KB total bundle, <100ms sync speed

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

### **Available Routes**
- **Landing Page**: http://localhost:5173/ - AI program discovery interface
- **Registration**: http://localhost:5173/register - Bidirectional registration system

## Project Structure

```
src/
├── components/
│   ├── LandingLayout.tsx      # Main landing page with split-screen design
│   ├── ChatInterface.tsx      # AI chat component with pattern matching
│   ├── registration/          # Bidirectional registration system
│   │   ├── RegistrationPage.tsx   # 70/30 registration layout
│   │   ├── RegistrationForm.tsx   # Form with real-time sync
│   │   └── RegistrationChat.tsx   # AI conversation interface
│   └── App.tsx               # Root application with routing
├── stores/
│   └── registrationStore.ts  # Zustand state management
├── index.css                 # Tailwind styles + Anthropic design tokens
└── main.tsx                 # Application entry point
```

## Design System

### Color Palette
- **Background**: Deep navy (#0F172A)
- **Primary Accent**: Anthropic orange (#FF6B35)
- **Card Backgrounds**: Dark gray (#1E293B)
- **Text**: White (#FFFFFF) and light gray (#94A3B8)

### Typography
- **Font**: Inter (400, 500, 600 weights)
- **Headings**: Large (2.5rem), Medium (1.5rem), Small (1.25rem)
- **Spacing**: 8px base unit system

## AI Query Patterns

### For Parents
- "Find robotics programs for my 10-year-old near Austin, Texas"
- "Show me beginner-friendly FLL teams starting in January"
- "What programs are available on weekends?"

### For Mentors
- "I'm an engineer wanting to start an FLL team in Seattle"
- "Show me mentoring opportunities that need my background"
- "What support do you provide for first-time mentors?"

### For Students
- "I want to learn robotics and compete with other kids"
- "Find programs that focus on programming and coding"
- "Show me FLL programs where I can be a team captain"

## Technology Stack

- **Frontend**: React 18 + TypeScript
- **Styling**: TailwindCSS with custom Anthropic design tokens
- **Build Tool**: Vite
- **Development**: Hot reload, TypeScript support, ESLint

## Development Commands

```bash
npm run dev     # Start development server
npm run build   # Build for production
npm run lint    # Run ESLint
npm run preview # Preview production build
```

## Implementation Status ✅

### **Phase 1: AI Landing Page**
- [x] Split-screen layout with Anthropic styling
- [x] Interactive chat interface with pattern-matched responses
- [x] Static content panel with hero section and features
- [x] Program recommendation cards with detailed information
- [x] Fully responsive design (desktop/tablet/mobile)
- [x] Accessibility features and keyboard navigation
- [x] Smooth animations and transitions

### **Phase 1.5: Bidirectional Registration**
- [x] 70/30 registration layout with dual interfaces
- [x] Real-time form ↔ chat synchronization
- [x] Intelligent field extraction from natural language
- [x] Contextual AI responses based on user input
- [x] Progress tracking and completion validation
- [x] Mobile-responsive modal design
- [x] Zustand state management integration

## 🌐 Platform Integration Strategy

### **Landing Page → Mentor Platform Flow**
1. **Discovery Phase**: Visitors use AI to find programs and mentors
2. **Seamless Transition**: Single sign-on from landing to mentor dashboard
3. **Data Continuity**: Conversation history and preferences carry forward
4. **Unified Experience**: Consistent design system across all platform components

### **Cross-Platform Intelligence**
- **Landing insights** inform mentor platform AI features
- **User behavior data** enhances dashboard personalization  
- **Successful matching patterns** improve platform-wide algorithms
- **Conversation flows** guide mentor interface development

### **Business Impact Targets**
- **Program Enrollment**: 40% increase in sign-ups from AI discovery
- **Mentor Acquisition**: 60% improvement in qualified applications
- **User Engagement**: Reduce bounce rate from 70% to 30%
- **Platform Stickiness**: >85% satisfaction with AI recommendations

## 🎯 Next Development Phases

### **Phase 2: Core Mentor Platform** (Weeks 5-8)
- [ ] Mentor authentication and profile management
- [ ] Program creation and student enrollment workflows  
- [ ] Split-screen mentor dashboard (traditional + AI interface)
- [ ] Real-time analytics and reporting

### **Phase 3: Advanced AI Integration** (Months 4-6)
- [ ] Student success prediction and risk assessment
- [ ] Automated scheduling and resource recommendations
- [ ] Proactive mentor insights and early warning systems
- [ ] Natural language program management

### **Phase 4: Enterprise Platform** (Months 6+)
- [ ] Multi-domain education platform foundation
- [ ] Advanced AI model training and deployment
- [ ] Enterprise features and scaling infrastructure  
- [ ] Broader education ecosystem integration

---

**MentorIQ is building the future of educational mentoring - one conversational interaction at a time.** 🤖✨