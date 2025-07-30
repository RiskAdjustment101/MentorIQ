import React, { useState, useRef, useEffect } from 'react';

interface Message {
  id: string;
  content: string;
  sender: 'user' | 'ai';
  timestamp: Date;
  programRecommendations?: ProgramRecommendation[];
}

interface ProgramRecommendation {
  id: string;
  name: string;
  mentor: string;
  price: string;
  location: string;
  spots: string;
  rating: number;
  description: string;
  ageRange: string;
  schedule: string;
}

export const ChatInterface: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      content: "Hi! I'm here to help you find the perfect FLL program. I can help parents find programs for their kids, mentors discover opportunities, or students explore FLL teams. What brings you here today?",
      sender: 'ai',
      timestamp: new Date(),
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const exampleQueries = [
    "Find robotics programs for my 10-year-old near Austin, Texas",
    "I'm an engineer wanting to start an FLL team in Seattle", 
    "Show me weekend programs with experienced mentors",
    "What programs are available for beginners starting in January?"
  ];

  const handleSendMessage = async (content: string) => {
    if (!content.trim()) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      content: content.trim(),
      sender: 'user',
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    setInputValue('');
    setIsTyping(true);

    // Simulate AI response delay
    setTimeout(() => {
      const aiResponse = generateAIResponse(content.trim());
      setMessages(prev => [...prev, aiResponse]);
      setIsTyping(false);
    }, 1000 + Math.random() * 1000);
  };

  const generateAIResponse = (userInput: string): Message => {
    const input = userInput.toLowerCase();
    const baseResponse: Omit<Message, 'content' | 'programRecommendations'> = {
      id: (Date.now() + 1).toString(),
      sender: 'ai',
      timestamp: new Date(),
    };

    // Parent queries - looking for programs
    if (input.includes('find') && (input.includes('program') || input.includes('team')) ||
        input.includes('my') && (input.includes('child') || input.includes('daughter') || input.includes('son') || input.includes('kid')) ||
        input.match(/\d+.year.old/)) {
      
      const mockPrograms: ProgramRecommendation[] = [
        {
          id: '1',
          name: 'Robotics Rockets',
          mentor: 'Sarah Chen, Mechanical Engineer',
          price: '$299/season',
          location: '2.3 miles away',
          spots: '3 spots left',
          rating: 4.9,
          description: 'Perfect for beginners with hands-on robotics and friendly competition prep.',
          ageRange: '9-14 years',
          schedule: 'Saturdays 10am-12pm'
        },
        {
          id: '2', 
          name: 'Tech Titans',
          mentor: 'Mike Rodriguez, Software Developer',
          price: '$349/season',
          location: '4.1 miles away',
          spots: 'Open enrollment',
          rating: 4.8,
          description: 'Focus on programming and advanced robotics for competitive teams.',
          ageRange: '10-15 years', 
          schedule: 'Wednesdays 4pm-6pm + Saturdays 9am-11am'
        }
      ];

      return {
        ...baseResponse,
        content: "Great! I found some excellent FLL programs near you. Based on what you're looking for, here are my top recommendations:",
        programRecommendations: mockPrograms
      };
    }

    // Mentor queries - wanting to start or join programs
    if (input.includes('mentor') || input.includes('start') && input.includes('team') ||
        input.includes('engineer') || input.includes('teach')) {
      
      return {
        ...baseResponse,
        content: "Wonderful! We need more passionate mentors like you. Here's how you can get started:\n\n• **Create your mentor profile** - Share your background and expertise\n• **Choose your approach** - Start a new team or join an existing program\n• **Get support** - Access our mentor toolkit and training resources\n• **Connect with families** - We'll help match you with interested students\n\nWould you like help setting up your mentor profile, or do you have questions about starting your first FLL team?"
      };
    }

    // Student queries - looking to join teams
    if (input.includes('student') || input.includes('learn robotics') || input.includes('compete') ||
        input.includes('team captain') || input.includes('programming')) {
      
      const mockPrograms: ProgramRecommendation[] = [
        {
          id: '3',
          name: 'Future Engineers',
          mentor: 'Dr. Lisa Park, Robotics Professor',  
          price: '$329/season',
          location: '1.8 miles away',
          spots: '2 spots left',
          rating: 5.0,
          description: 'Advanced program for students with prior FLL experience.',
          ageRange: '12-16 years',
          schedule: 'Tuesdays & Thursdays 3:30pm-5:30pm'
        }
      ];

      return {
        ...baseResponse,
        content: "Awesome! FLL is a great way to dive into robotics and STEM. I found some programs that might be perfect for you:",
        programRecommendations: mockPrograms
      };
    }

    // Location-specific queries
    if (input.includes('near') || input.includes('in ') || 
        input.match(/texas|austin|seattle|california|new york|florida/)) {
      
      return {
        ...baseResponse,
        content: "I'm searching for FLL programs in your area! While I found your location, I'd love to know more to give you the best recommendations:\n\n• What age range are you looking for?\n• Any preferred meeting times (weekdays, weekends)?\n• Experience level (beginner, intermediate, advanced)?\n• Any specific interests (programming, mechanical design, competition focus)?\n\nThis will help me find the perfect match!"
      };
    }

    // Pricing queries
    if (input.includes('cost') || input.includes('price') || input.includes('expensive') || 
        input.includes('budget') || input.includes('financial')) {
      
      return {
        ...baseResponse,
        content: "Great question! FLL program costs typically range from $250-$400 per season, which usually includes:\n\n• **Materials & Equipment** - LEGO robot kit, competition mat, challenge pieces\n• **Mentor Instruction** - Weekly coaching and guidance\n• **Competition Registration** - Entry fees for tournaments\n• **Resources** - Access to online materials and support\n\nMany programs offer:\n• Payment plans to spread costs over the season\n• Scholarships for families with financial need\n• Sibling discounts\n\nWould you like me to show you programs in a specific price range?"
      };
    }

    // General/scheduling queries
    if (input.includes('when') || input.includes('schedule') || input.includes('time') ||
        input.includes('weekend') || input.includes('weekday')) {
      
      return {
        ...baseResponse,
        content: "FLL programs typically run from September through February, with most teams meeting:\n\n• **Weekly Sessions**: 1.5-2 hours per week\n• **Common Times**: Weekday afternoons (3-6pm) or weekend mornings\n• **Season Schedule**: September (team formation) → October-December (robot building) → January-February (competitions)\n\nPopular meeting patterns:\n• Saturdays 10am-12pm (great for families)\n• Weekday afternoons 4-6pm (after school)\n• Sunday afternoons 2-4pm\n\nWhat schedule works best for your family?"
      };
    }

    // Default response for unclear queries
    return {
      ...baseResponse,
      content: "I'd love to help you find the perfect FLL program! Could you tell me a bit more about what you're looking for?\n\nI can help with:\n• **Parents**: Finding programs for your child\n• **Mentors**: Starting or joining a team as a coach\n• **Students**: Discovering teams to join\n\nOr try asking something like:\n• \"Find programs for my 11-year-old near [your city]\"\n• \"I want to mentor an FLL team\"\n• \"Show me weekend programs for beginners\""
    };
  };

  const handleExampleQuery = (query: string) => {
    handleSendMessage(query);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage(inputValue);
    }
  };

  return (
    <div className="h-full bg-slate-800 flex flex-col">
      {/* Chat Header */}
      <div className="p-4 border-b border-slate-700">
        <h2 className="text-lg font-semibold mb-1">Find Your Perfect FLL Program</h2>
        <p className="text-slate-400 text-xs">Ask me anything about programs, mentors, or getting started!</p>
      </div>
      
      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 chat-scroll">
        <div className="space-y-4">
          {messages.map((message) => (
            <MessageBubble key={message.id} message={message} />
          ))}
          
          {isTyping && <TypingIndicator />}
          
          {/* Example queries - only show if first message */}
          {messages.length === 1 && (
            <div className="space-y-3 mt-6">
              <p className="text-slate-400 text-sm">Try asking:</p>
              {exampleQueries.map((query, index) => (
                <button
                  key={index}
                  onClick={() => handleExampleQuery(query)}
                  className="block w-full text-left p-3 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm transition-colors border border-slate-600 hover:border-slate-500"
                >
                  "{query}"
                </button>
              ))}
            </div>
          )}
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
            placeholder="Ask about FLL programs, mentors, or locations..."
            className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-colors"
          />
          <button
            onClick={() => handleSendMessage(inputValue)}
            disabled={!inputValue.trim()}
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
  message: Message;
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
          <p className="text-sm leading-relaxed whitespace-pre-line">{message.content}</p>
          
          {/* Program Recommendations */}
          {message.programRecommendations && (
            <div className="mt-4 space-y-3">
              {message.programRecommendations.map((program) => (
                <ProgramCard key={program.id} program={program} />
              ))}
            </div>
          )}
        </div>
        <div className={`text-xs text-slate-400 mt-1 ${isUser ? 'text-right' : 'text-left'}`}>
          {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </div>
      </div>
    </div>
  );
};

interface ProgramCardProps {
  program: ProgramRecommendation;
}

const ProgramCard: React.FC<ProgramCardProps> = ({ program }) => {
  return (
    <div className="bg-slate-800 border border-slate-600 rounded-lg p-4 mt-3">
      <div className="flex justify-between items-start mb-2">
        <h3 className="font-semibold text-white">{program.name}</h3>
        <div className="flex items-center text-xs">
          <span className="text-yellow-400">★</span>
          <span className="ml-1 text-slate-300">{program.rating}</span>
        </div>
      </div>
      
      <p className="text-sm text-slate-400 mb-2">{program.mentor}</p>
      <p className="text-sm text-slate-300 mb-3">{program.description}</p>
      
      <div className="space-y-2 text-xs text-slate-400">
        <div className="flex justify-between">
          <span>📍 {program.location}</span>
          <span className="text-orange-400 font-semibold">{program.price}</span>
        </div>
        <div className="flex justify-between">
          <span>👥 {program.ageRange}</span>
          <span className="text-green-400">{program.spots}</span>
        </div>
        <div>📅 {program.schedule}</div>
      </div>
      
      <div className="flex space-x-2 mt-3">
        <button className="flex-1 px-3 py-2 bg-orange-500 hover:bg-orange-600 text-white rounded text-xs font-medium transition-colors">
          Contact Mentor
        </button>
        <button className="flex-1 px-3 py-2 border border-slate-500 hover:border-slate-400 text-slate-300 rounded text-xs font-medium transition-colors">
          Learn More
        </button>
      </div>
    </div>
  );
};

const TypingIndicator: React.FC = () => {
  return (
    <div className="flex justify-start animate-fade-in">
      <div className="bg-slate-700 rounded-lg p-4 max-w-xs">
        <div className="flex space-x-1">
          <div className="w-2 h-2 bg-slate-400 rounded-full animate-pulse"></div>
          <div className="w-2 h-2 bg-slate-400 rounded-full animate-pulse" style={{ animationDelay: '0.2s' }}></div>
          <div className="w-2 h-2 bg-slate-400 rounded-full animate-pulse" style={{ animationDelay: '0.4s' }}></div>
        </div>
      </div>
    </div>
  );
};