import { create } from 'zustand';

export type UserType = 'parent' | 'mentor';

export interface Message {
  id: string;
  content: string;
  sender: 'user' | 'ai';
  timestamp: Date;
  triggeredField?: 'name' | 'email' | 'userType';
}

export interface RegistrationData {
  name: string;
  email: string;
  userType: UserType | null;
}

export interface RegistrationState {
  // Form data
  registrationData: RegistrationData;
  
  // UI state
  activeField: string | null;
  completionStatus: {
    name: boolean;
    email: boolean;
    userType: boolean;
  };
  
  // Chat state
  messages: Message[];
  currentQuestion: string | null;
  isAiTyping: boolean;
  
  // Metadata
  entryMethod: 'form' | 'chat' | 'mixed';
  startedAt: Date | null;
  lastInteractionAt: Date | null;
  
  // Actions
  updateField: (field: keyof RegistrationData, value: string | UserType | null) => void;
  setActiveField: (field: string | null) => void;
  addMessage: (message: Omit<Message, 'id' | 'timestamp'>) => void;
  setAiTyping: (isTyping: boolean) => void;
  setCurrentQuestion: (question: string | null) => void;
  setEntryMethod: (method: 'form' | 'chat' | 'mixed') => void;
  updateInteractionTime: () => void;
  reset: () => void;
}

const initialRegistrationData: RegistrationData = {
  name: '',
  email: '',
  userType: null,
};

const initialCompletionStatus = {
  name: false,
  email: false,
  userType: false,
};

export const useRegistrationStore = create<RegistrationState>((set, get) => ({
  // Initial state
  registrationData: initialRegistrationData,
  activeField: null,
  completionStatus: initialCompletionStatus,
  messages: [
    {
      id: '1',
      content: "Hi! Welcome to MentorIQ. I'm here to help you get started. What's your name?",
      sender: 'ai',
      timestamp: new Date(),
    }
  ],
  currentQuestion: 'name',
  isAiTyping: false,
  entryMethod: 'chat',
  startedAt: null,
  lastInteractionAt: null,

  // Actions
  updateField: (field, value) => {
    const state = get();
    const newData = { ...state.registrationData, [field]: value };
    const newCompletion = { ...state.completionStatus };
    
    // Update completion status
    switch (field) {
      case 'name':
        newCompletion.name = typeof value === 'string' && value.trim().length > 0;
        break;
      case 'email':
        newCompletion.email = typeof value === 'string' && value.includes('@') && value.includes('.');
        break;
      case 'userType':
        newCompletion.userType = value !== null;
        break;
    }
    
    // Set entry method based on first interaction
    let entryMethod = state.entryMethod;
    if (state.startedAt === null) {
      entryMethod = 'form';
    }
    
    set({
      registrationData: newData,
      completionStatus: newCompletion,
      entryMethod,
      startedAt: state.startedAt || new Date(),
      lastInteractionAt: new Date(),
    });
  },

  setActiveField: (field) => set({ activeField: field }),

  addMessage: (messageData) => {
    const state = get();
    const newMessage: Message = {
      ...messageData,
      id: Date.now().toString(),
      timestamp: new Date(),
    };
    
    // Set entry method based on first message
    let entryMethod = state.entryMethod;
    if (state.startedAt === null && messageData.sender === 'user') {
      entryMethod = 'chat';
    } else if (state.entryMethod !== 'chat' && messageData.sender === 'user') {
      entryMethod = 'mixed';
    }
    
    set({
      messages: [...state.messages, newMessage],
      entryMethod,
      startedAt: state.startedAt || new Date(),
      lastInteractionAt: new Date(),
    });
  },

  setAiTyping: (isTyping) => set({ isAiTyping: isTyping }),

  setCurrentQuestion: (question) => set({ currentQuestion: question }),

  setEntryMethod: (method) => set({ entryMethod: method }),

  updateInteractionTime: () => set({ lastInteractionAt: new Date() }),

  reset: () => set({
    registrationData: initialRegistrationData,
    activeField: null,
    completionStatus: initialCompletionStatus,
    messages: [
      {
        id: '1',
        content: "Hi! Welcome to MentorIQ. I'm here to help you get started. What's your name?",
        sender: 'ai',
        timestamp: new Date(),
      }
    ],
    currentQuestion: 'name',
    isAiTyping: false,
    entryMethod: 'chat',
    startedAt: null,
    lastInteractionAt: null,
  }),
}));