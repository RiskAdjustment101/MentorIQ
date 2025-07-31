/**
 * AI Service for MentorIQ Platform
 * Integrates with FastAPI backend using Ollama for intelligent responses
 * Trained on comprehensive platform knowledge
 */

import { Message } from '../stores/registrationStore';

interface AIResponse {
  response: string;
  context: string;
  suggestions?: string[];
  timestamp: string;
}

interface RegistrationAIResponse extends AIResponse {
  field_updates?: {
    name?: string;
    email?: string;
    userType?: 'parent' | 'mentor';
  };
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
}

class AIService {
  private baseURL: string;
  
  constructor() {
    // Use environment variable or default to local development
    this.baseURL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
  }

  /**
   * Get intelligent response for landing page program discovery
   */
  async getLandingResponse(
    query: string,
    userContext?: Record<string, any>,
    conversationHistory: Message[] = []
  ): Promise<AIResponse & { programRecommendations?: ProgramRecommendation[] }> {
    try {
      const response = await fetch(`${this.baseURL}/api/ai/chat/landing`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          query,
          user_context: {
            page: 'landing',
            timestamp: new Date().toISOString(),
            ...userContext,
          },
          conversation_history: conversationHistory.map(msg => ({
            content: msg.content,
            sender: msg.sender,
            timestamp: msg.timestamp.toISOString(),
          })),
        }),
      });

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
      }

      const data: AIResponse = await response.json();
      
      // Check if response indicates program recommendations should be shown
      const shouldShowRecommendations = this.shouldGenerateRecommendations(query, data.response);
      
      return {
        ...data,
        programRecommendations: shouldShowRecommendations ? this.generateMockRecommendations() : undefined,
      };
      
    } catch (error) {
      console.error('AI Service Error (Landing):', error);
      
      // Fallback to basic response if AI service is unavailable
      return this.getFallbackLandingResponse(query);
    }
  }

  /**
   * Get intelligent response for registration with field extraction
   */
  async getRegistrationResponse(
    query: string,
    registrationData: any,
    conversationHistory: Message[] = []
  ): Promise<RegistrationAIResponse> {
    try {
      const response = await fetch(`${this.baseURL}/api/ai/chat/registration`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          query,
          registration_data: registrationData,
          conversation_history: conversationHistory.map(msg => ({
            content: msg.content,
            sender: msg.sender,
            timestamp: msg.timestamp.toISOString(),
          })),
        }),
      });

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
      }

      const data: RegistrationAIResponse = await response.json();
      return data;
      
    } catch (error) {
      console.error('AI Service Error (Registration):', error);
      
      // Fallback to basic field extraction if AI service is unavailable
      return this.getFallbackRegistrationResponse(query, registrationData);
    }
  }

  /**
   * Check AI service health
   */
  async checkHealth(): Promise<{ status: string; service: string }> {
    try {
      const response = await fetch(`${this.baseURL}/api/ai/health`);
      return await response.json();
    } catch (error) {
      console.warn('AI service health check failed:', error);
      return { status: 'unavailable', service: 'MentorIQ AI Assistant' };
    }
  }

  /**
   * Get platform knowledge summary (for debugging)
   */
  async getKnowledgeSummary(): Promise<any> {
    try {
      const response = await fetch(`${this.baseURL}/api/ai/knowledge/summary`);
      return await response.json();
    } catch (error) {
      console.error('Failed to get knowledge summary:', error);
      return null;
    }
  }

  // Private helper methods

  private shouldGenerateRecommendations(query: string, response: string): boolean {
    const triggerWords = [
      'program', 'team', 'find', 'show', 'recommend', 'match', 
      'suitable', 'available', 'near', 'location'
    ];
    
    const queryLower = query.toLowerCase();
    const responseLower = response.toLowerCase();
    
    return triggerWords.some(word => 
      queryLower.includes(word) || responseLower.includes(word)
    );
  }

  private generateMockRecommendations(): ProgramRecommendation[] {
    // Mock recommendations for development - replace with actual API data
    return [
      {
        id: '1',
        name: 'Robotics Rockets',
        mentor: 'Sarah Chen, Mechanical Engineer',
        price: '$299/season',
        location: '2.3 miles away',
        spots: '3 spots left',
        rating: 4.9,
        description: 'Perfect for beginners with hands-on robotics and friendly competition prep.',
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
      },
    ];
  }

  private getFallbackLandingResponse(query: string): AIResponse & { programRecommendations?: ProgramRecommendation[] } {
    const queryLower = query.toLowerCase();
    
    if (queryLower.includes('parent') || queryLower.includes('child')) {
      return {
        response: "I'd love to help you find the perfect FLL program for your child! While our AI assistant is temporarily unavailable, I can still guide you through program discovery. What specific aspects are you looking for - location, schedule, experience level, or mentor background?",
        context: 'landing',
        suggestions: [
          'Tell me about program costs',
          'How do I evaluate mentors?',
          'What age groups do you serve?',
          'Take me to registration'
        ],
        timestamp: new Date().toISOString(),
      };
    }
    
    if (queryLower.includes('mentor') || queryLower.includes('teach')) {
      return {
        response: "Great to meet a potential mentor! While our AI is temporarily offline, I can still help you get started with mentoring opportunities. Are you looking to start a new FLL team or join an existing program?",
        context: 'landing',
        suggestions: [
          'How does mentoring work?',
          'What support do you provide?',
          'Create my mentor profile',
          'Show me time commitments'
        ],
        timestamp: new Date().toISOString(),
      };
    }
    
    return {
      response: "Welcome to MentorIQ! I'm here to help you discover FLL programs and mentors. Our AI assistant is currently being enhanced, but I can still help you get started. What brings you here today?",
      context: 'landing',
      suggestions: [
        'I\'m a parent looking for programs',
        'I want to become a mentor',
        'Tell me about your platform',
        'How does this work?'
      ],
      timestamp: new Date().toISOString(),
    };
  }

  private getFallbackRegistrationResponse(query: string, registrationData: any): RegistrationAIResponse {
    // Basic field extraction for fallback
    const fieldUpdates: any = {};
    
    // Simple name extraction
    const nameMatch = query.match(/(?:i'm|i am|my name is|call me)\s+([a-zA-Z\s]+)/i);
    if (nameMatch) {
      fieldUpdates.name = nameMatch[1].trim();
    }
    
    // Email extraction
    const emailMatch = query.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/);
    if (emailMatch) {
      fieldUpdates.email = emailMatch[0];
    }
    
    // User type extraction
    if (query.toLowerCase().includes('parent') || query.toLowerCase().includes('child')) {
      fieldUpdates.userType = 'parent';
    } else if (query.toLowerCase().includes('mentor') || query.toLowerCase().includes('teach')) {
      fieldUpdates.userType = 'mentor';
    }
    
    // Generate appropriate response
    let response = "Thanks for that information! ";
    
    if (fieldUpdates.name) {
      response += `Hi ${fieldUpdates.name}! `;
    }
    
    if (fieldUpdates.email) {
      response += "I've got your email address. ";
    }
    
    if (fieldUpdates.userType === 'parent') {
      response += "Wonderful! We're excited to help you find the perfect FLL program for your child.";
    } else if (fieldUpdates.userType === 'mentor') {
      response += "Fantastic! We need more passionate mentors like you.";
    } else {
      response += "I'm here to help you complete your registration. You can tell me your information or use the form - whatever works best for you!";
    }
    
    return {
      response,
      context: 'registration',
      field_updates: fieldUpdates,
      timestamp: new Date().toISOString(),
    };
  }
}

// Export singleton instance
export const aiService = new AIService();