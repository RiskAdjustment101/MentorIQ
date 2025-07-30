# MentorIQ Landing Page - AI-First Program Discovery

An AI-enhanced landing page for FLL (FIRST LEGO League) program discovery, built with React + TypeScript and Anthropic design principles.

## Features

### 🎯 Hybrid Interface Design
- **70/30 Split-screen Layout**: Static content + conversational AI assistant
- **Anthropic Design System**: Dark theme, orange accents (#FF6B35), Inter font
- **Fully Responsive**: Desktop, tablet, and mobile optimized

### 🤖 AI Program Discovery
- **Smart Query Processing**: Pattern-matched responses for parents, mentors, and students
- **Personalized Recommendations**: Dynamic program matching with detailed cards
- **Conversational Flows**: Natural language interaction for program discovery

### 📱 Responsive Experience
- **Desktop**: 70/30 split-screen layout
- **Tablet**: 50/50 balanced experience with collapsible chat
- **Mobile**: Stacked layout with floating chat button and modal overlay

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## Project Structure

```
src/
├── components/
│   ├── LandingLayout.tsx      # Main layout with split-screen design
│   ├── ChatInterface.tsx      # AI chat component with pattern matching
│   └── App.tsx               # Root application component
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

- [x] Split-screen layout with Anthropic styling
- [x] Interactive chat interface with pattern-matched responses
- [x] Static content panel with hero section and features
- [x] Program recommendation cards with detailed information
- [x] Fully responsive design (desktop/tablet/mobile)
- [x] Accessibility features and keyboard navigation
- [x] Smooth animations and transitions

## Next Steps

- [ ] Backend integration for real program data
- [ ] Advanced NLP for query processing
- [ ] User analytics and interaction tracking
- [ ] A/B testing framework
- [ ] Integration with mentor platform