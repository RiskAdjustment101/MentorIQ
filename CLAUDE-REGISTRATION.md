# CLAUDE-REGISTRATION.md - Registration Page Specification

## **Current Development Focus**

### **Feature: Bidirectional Registration System**
Build a conversational registration page that allows users to register either through AI chat or traditional form, with real-time synchronization between both interfaces.

### **Success Criteria:**
- [ ] Users can complete registration via chat conversation
- [ ] Users can complete registration via traditional form
- [ ] Form fields update in real-time when using chat
- [ ] AI assistant personalizes responses based on form inputs
- [ ] 70/30 split-screen layout following Anthropic design system
- [ ] Parent and Mentor user types supported (no students)

---

## **Product Requirements**

### **Core Concept**
A registration page that demonstrates the platform's AI capabilities from the first interaction:
- **Left Side (70%):** Dynamic registration form that updates in real-time
- **Right Side (30%):** AI assistant that guides users conversationally
- **Bidirectional Sync:** Changes in either interface update the other

### **User Types**
```
Supported Registration Types:
├── Parent: Looking for FLL programs for their children
└── Mentor: Wanting to lead or assist with FLL teams
(Students: Not included in current phase)
```

---

## **User Flows**

### **Flow 1: Conversational Registration**
```
User Journey:
1. User sees AI assistant greeting
2. AI asks for name → User responds in chat
3. Form field populates with name automatically
4. AI asks for email → User responds in chat
5. Form field populates with email
6. AI asks for user type → User selects in chat
7. Form radio button updates
8. AI confirms and creates account
```

### **Flow 2: Traditional Form Registration**
```
User Journey:
1. User starts typing in name field
2. AI acknowledges: "Hi [Name], I see you're getting started..."
3. User enters email
4. AI provides contextual response based on email domain
5. User selects role (Parent/Mentor)
6. AI offers role-specific encouragement
7. User submits form
```

### **Flow 3: Mixed Interaction**
Users can seamlessly switch between form and chat at any point, with both interfaces maintaining synchronization.

---

## **Technical Specifications**

### **Frontend Structure**
Following the established React + TypeScript patterns from CLAUDE.md:

```
src/components/registration/
├── RegistrationPage/          # Main container component
├── RegistrationForm/          # Form component (left side)
├── RegistrationChat/          # Chat component (right side)
└── shared/                    # Shared state and utilities
```

### **State Management**
Using Zustand (as specified in tech stack) for bidirectional state synchronization:

```
Registration State:
├── Form Data (name, email, userType)
├── UI State (activeField, completionStatus)
├── Chat State (messages, currentQuestion)
└── Metadata (entryMethod, timestamps)
```

### **Backend Integration**
Following the Python/FastAPI patterns from CLAUDE.md:

```
API Endpoints:
├── POST /api/registration/create-account
├── POST /api/registration/validate-field
├── GET /api/registration/check-email-availability
└── POST /api/registration/chat-message
```

---

## **Design Implementation**

### **Following Anthropic UI Design Language**
Reference Claude-Landing.md for:
- Color palette (Deep navy background, Anthropic orange accents)
- Typography (Inter font, specified sizes)
- Component styling (Rounded corners, dark theme)
- Animation patterns (Smooth transitions, hover effects)

### **Layout Specifications**
```
Desktop (1200px+):
├── Container: 1200px max-width
├── Left Panel: 70% width (840px)
├── Right Panel: 30% width (360px)
├── Gap: 24px between panels
└── Padding: Following 8px base unit system
```

### **Responsive Behavior**
```
Tablet (768px - 1199px):
├── Split: 60/40 ratio
└── Chat: Collapsible panel

Mobile (< 768px):
├── Stack: Vertical layout
├── Chat: Modal overlay
└── Form: Full width
```

---

## **AI Assistant Behavior**

### **Conversation Patterns**

#### **Initial Greeting**
- Warm, welcoming tone
- Clear value proposition
- Natural conversation starter

#### **Information Collection**
- One question at a time
- Natural language processing
- Graceful error handling
- Progressive disclosure

#### **Contextual Responses**
Based on user inputs, provide relevant responses:
- Educational institution emails → Education background acknowledgment
- Tech company domains → Technical expertise recognition
- Parent selection → Family-focused benefits
- Mentor selection → Leadership and impact focus

### **Personalization Engine**
```
Context Detection:
├── Email domain analysis
├── Name pattern recognition
├── Response timing patterns
├── Geographic inference (if provided)
└── Industry/background inference
```

---

## **Implementation Phases**

### **Phase 1: Basic Structure (Day 1-2)**
- [ ] Create 70/30 split-screen layout
- [ ] Build static registration form
- [ ] Implement basic chat UI
- [ ] Set up Zustand state management

### **Phase 2: Bidirectional Sync (Day 3-4)**
- [ ] Implement form → chat state updates
- [ ] Implement chat → form state updates
- [ ] Add real-time field population animations
- [ ] Create validation logic

### **Phase 3: AI Intelligence (Day 5-7)**
- [ ] Add conversation flow logic
- [ ] Implement contextual responses
- [ ] Add email domain detection
- [ ] Create personalization patterns

### **Phase 4: Polish & Testing (Day 8-10)**
- [ ] Add loading states and error handling
- [ ] Implement accessibility features
- [ ] Mobile responsive design
- [ ] User testing and refinement

---

## **Development Guidelines**

### **Follow Established Patterns**
- Use existing CLAUDE.md development boundaries
- Follow Meta's 0-to-1 development strategy
- Implement Facebook engineering best practices
- Use approved tech stack only

### **Change Management**
- Follow strict change protocol from CLAUDE.md
- Document all changes
- Test incrementally
- Commit frequently with descriptive messages

### **Quality Standards**
- 80% test coverage minimum
- Accessibility WCAG 2.1 AA compliance
- Performance: <2s response time
- Mobile-first responsive design

---

## **Integration Points**

### **With Core Platform**
- Registration data flows to mentor dashboard
- User preferences carry forward
- Authentication tokens generated
- Onboarding flow triggered post-registration

### **With Landing Page**
- Consistent design language
- Shared AI conversation patterns
- Unified user experience
- Analytics tracking consistency

---

## **Success Metrics**

### **User Experience**
- Registration completion rate >85%
- Average time to complete <2 minutes
- User satisfaction score >4.5/5
- Form abandonment rate <15%

### **Technical Performance**
- Page load time <1.5s
- Chat response time <500ms
- Zero-downtime deployment
- Error rate <0.1%

### **Business Impact**
- Increased registration conversion by 40%
- Higher quality user profiles (more complete data)
- Better user segmentation (Parent vs Mentor)
- Improved onboarding engagement

---

## **Security Considerations**

### **Data Protection**
- Email validation and sanitization
- Rate limiting on registration attempts
- CAPTCHA for bot prevention
- Secure password requirements

### **Privacy Compliance**
- COPPA compliance for parent registrations
- Clear data usage disclosure
- Opt-in for communications
- GDPR-ready architecture

---

## **Next Steps**

1. **Confirm Requirements:** Verify this specification meets the vision
2. **Set Up Base Structure:** Create component folders and initial files
3. **Implement Layout:** Build 70/30 split-screen with Anthropic styling
4. **Add Core Functionality:** Form fields and basic chat interface
5. **Enable Synchronization:** Bidirectional state management
6. **Iterate with Feedback:** Test with users and refine

This specification aligns with the existing CLAUDE.md patterns while focusing specifically on the registration page requirements.