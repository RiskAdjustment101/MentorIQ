import React, { useState, useRef, useEffect } from 'react';
import { useRegistrationStore, UserType } from '../../stores/registrationStore';

export const RegistrationChat: React.FC = () => {
  const [inputValue, setInputValue] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  
  const {
    messages,
    currentQuestion,
    isAiTyping,
    completionStatus,
    updateField,
    addMessage,
    setAiTyping,
    setCurrentQuestion,
    updateInteractionTime,
  } = useRegistrationStore();

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const processUserMessage = (message: string) => {
    
    // Add user message
    addMessage({
      content: message,
      sender: 'user',
    });
    
    setInputValue('');
    setAiTyping(true);
    
    // Process message based on current question context
    setTimeout(() => {
      let aiResponse = '';
      let nextQuestion = currentQuestion;
      
      if (currentQuestion === 'name' && !completionStatus.name) {
        // Extract potential name from message
        const potentialName = extractName(message);
        if (potentialName) {
          updateField('name', potentialName);
          aiResponse = `Great to meet you, ${potentialName}! Now, what's your email address?`;
          nextQuestion = 'email';
        } else {
          aiResponse = "I'd love to know your name! Could you tell me what I should call you?";
        }
      } else if (currentQuestion === 'email' && !completionStatus.email) {
        // Extract potential email from message
        const potentialEmail = extractEmail(message);
        if (potentialEmail) {
          updateField('email', potentialEmail);
          const domain = potentialEmail.split('@')[1];
          let domainResponse = '';
          
          if (domain?.includes('edu')) {
            domainResponse = ' I see you\'re from an educational institution - that\'s wonderful!';
          } else if (domain?.includes('gmail') || domain?.includes('yahoo') || domain?.includes('hotmail')) {
            domainResponse = ' Got it!';
          } else {
            domainResponse = ` Great to have you joining from ${domain}!`;
          }
          
          aiResponse = `Perfect! I have your email as ${potentialEmail}.${domainResponse} Are you here as a parent looking for programs for your child, or as a mentor wanting to help with FLL teams?`;
          nextQuestion = 'userType';
        } else {
          aiResponse = "I need your email address to create your account. Could you share that with me?";
        }
      } else if (currentQuestion === 'userType' && !completionStatus.userType) {
        // Determine user type from message
        const userType = extractUserType(message);
        if (userType) {
          updateField('userType', userType);
          const responses = {
            parent: "Wonderful! We're excited to help you find the perfect FLL program for your child. Our platform connects families with amazing mentors and teams in your area. You're all set to explore programs!",
            mentor: "Fantastic! We need more passionate mentors like you. Whether you're looking to start a new team or join an existing program, we'll help you make a real impact on students' lives. Welcome to the mentor community!",
          };
          aiResponse = responses[userType];
          nextQuestion = 'complete';
        } else {
          aiResponse = "Are you joining as a parent (looking for programs for your child) or as a mentor (wanting to help with FLL teams)? Just let me know which one describes you!";
        }
      } else if (nextQuestion === 'complete') {
        // Registration complete responses
        const responses = [
          "Is there anything else you'd like to know about MentorIQ?",
          "I'm here if you have any questions about getting started!",
          "Feel free to ask me about programs, mentoring, or anything else!",
        ];
        aiResponse = responses[Math.floor(Math.random() * responses.length)];
      } else {
        // Handle general conversation or clarifications
        aiResponse = generateContextualResponse(message);
      }
      
      setAiTyping(false);
      setCurrentQuestion(nextQuestion);
      addMessage({
        content: aiResponse,
        sender: 'ai',
      });
    }, 1000 + Math.random() * 1000);
  };

  const extractName = (message: string): string | null => {
    // Simple name extraction - look for patterns like "I'm X", "My name is X", or just a capitalized word
    const patterns = [
      /(?:i'm|i am|my name is|call me)\s+([a-zA-Z\s]+)/i,
      /^([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)$/,
    ];
    
    for (const pattern of patterns) {
      const match = message.match(pattern);
      if (match && match[1]) {
        return match[1].trim();
      }
    }
    
    // If message is short and looks like a name
    if (message.length < 50 && /^[A-Za-z\s]+$/.test(message)) {
      return message.trim();
    }
    
    return null;
  };

  const extractEmail = (message: string): string | null => {
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/;
    const match = message.match(emailRegex);
    return match ? match[0] : null;
  };

  const extractUserType = (message: string): UserType | null => {
    const lowerMessage = message.toLowerCase();
    
    if (lowerMessage.includes('parent') || lowerMessage.includes('child') || lowerMessage.includes('kid') || lowerMessage.includes('son') || lowerMessage.includes('daughter')) {
      return 'parent';
    }
    
    if (lowerMessage.includes('mentor') || lowerMessage.includes('teach') || lowerMessage.includes('coach') || lowerMessage.includes('help') || lowerMessage.includes('lead')) {
      return 'mentor';
    }
    
    return null;
  };

  const generateContextualResponse = (message: string): string => {
    const lowerMessage = message.toLowerCase();
    
    if (lowerMessage.includes('help') || lowerMessage.includes('question')) {
      return "I'm here to help! I can assist you with registering for MentorIQ, finding programs, or connecting with mentors.";
    }
    
    if (lowerMessage.includes('program') || lowerMessage.includes('team')) {
      return "Great question about programs! Once you complete registration, you'll be able to browse all available FLL programs in your area.";
    }
    
    if (lowerMessage.includes('cost') || lowerMessage.includes('price') || lowerMessage.includes('fee')) {
      return "Program costs vary by location and mentor. You'll see detailed pricing information when browsing programs after registration.";
    }
    
    return "Thanks for sharing that! Is there anything specific about MentorIQ or FLL programs you'd like to know more about?";
  };

  const handleSendMessage = () => {
    if (inputValue.trim()) {
      processUserMessage(inputValue.trim());
      updateInteractionTime();
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const getCompletionMessage = () => {
    const completed = Object.values(completionStatus).filter(Boolean).length;
    if (completed === 3) {
      return "🎉 Registration complete! You're all set.";
    } else if (completed === 2) {
      return "Almost there! Just one more step.";
    } else if (completed === 1) {
      return "Great start! A couple more details needed.";
    }
    return "Let's get you registered!";
  };

  return (
    <div className="h-full flex flex-col">
      {/* Chat Header */}
      <div className="p-4 border-b border-slate-700">
        <h2 className="text-lg font-semibold mb-1">Registration Assistant</h2>
        <p className="text-xs text-slate-400">{getCompletionMessage()}</p>
      </div>
      
      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 chat-scroll">
        <div className="space-y-4">
          {messages.map((message) => (
            <MessageBubble key={message.id} message={message} />
          ))}
          
          {isAiTyping && <TypingIndicator />}
        </div>
        <div ref={messagesEndRef} />
      </div>
      
      {/* Chat Input */}
      <div className="p-4 border-t border-slate-700">
        <div className="flex space-x-3">
          <input
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Type your response here..."
            className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-4 py-3 text-sm text-white placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-colors"
            disabled={isAiTyping}
          />
          <button
            onClick={handleSendMessage}
            disabled={!inputValue.trim() || isAiTyping}
            className="px-4 py-3 bg-orange-500 hover:bg-orange-600 disabled:bg-slate-600 disabled:cursor-not-allowed rounded-lg transition-colors"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
            </svg>
          </button>
        </div>
      </div>
    </div>
  );
};

interface MessageBubbleProps {
  message: {
    id: string;
    content: string;
    sender: 'user' | 'ai';
    timestamp: Date;
  };
}

const MessageBubble: React.FC<MessageBubbleProps> = ({ message }) => {
  const isUser = message.sender === 'user';
  
  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'} animate-fade-in`}>
      <div className={`max-w-xs ${isUser ? 'order-2' : 'order-1'}`}>
        <div className={`rounded-lg p-3 ${
          isUser 
            ? 'bg-orange-500 text-white animate-slide-in-right' 
            : 'bg-slate-700 text-white animate-slide-in-left'
        }`}>
          <p className="text-sm leading-relaxed">{message.content}</p>
        </div>
        <div className={`text-xs text-slate-500 mt-1 ${isUser ? 'text-right' : 'text-left'}`}>
          {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </div>
      </div>
    </div>
  );
};

const TypingIndicator: React.FC = () => {
  return (
    <div className="flex justify-start animate-fade-in">
      <div className="bg-slate-700 rounded-lg p-3 max-w-xs">
        <div className="flex space-x-1">
          <div className="w-2 h-2 bg-slate-400 rounded-full animate-pulse"></div>
          <div className="w-2 h-2 bg-slate-400 rounded-full animate-pulse" style={{ animationDelay: '0.2s' }}></div>
          <div className="w-2 h-2 bg-slate-400 rounded-full animate-pulse" style={{ animationDelay: '0.4s' }}></div>
        </div>
      </div>
    </div>
  );
};