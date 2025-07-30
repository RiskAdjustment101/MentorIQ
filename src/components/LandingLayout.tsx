import React, { useState } from 'react';
import { ChatInterface } from './ChatInterface';

export const LandingLayout: React.FC = () => {
  const [isChatOpen, setIsChatOpen] = useState(false);

  return (
    <div className="min-h-screen bg-slate-900 text-white font-inter">
      {/* Desktop and Tablet Layout */}
      <div className="hidden md:flex h-screen">
        {/* Static Content Panel - 70% width */}
        <div className="w-7/10 flex flex-col overflow-y-auto">
          <StaticContentPanel />
        </div>
        
        {/* AI Chat Panel - 30% width */}
        <div className="w-3/10 border-l border-slate-700">
          <ChatInterface />
        </div>
      </div>

      {/* Mobile Layout */}
      <div className="md:hidden relative">
        {/* Static Content */}
        <div className="min-h-screen">
          <StaticContentPanel />
        </div>
        
        {/* Floating Chat Button */}
        <button
          onClick={() => setIsChatOpen(true)}
          className="fixed bottom-6 right-6 w-14 h-14 bg-orange-500 hover:bg-orange-600 rounded-full shadow-lg flex items-center justify-center transition-all duration-300 z-40"
          aria-label="Open AI assistant"
        >
          <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
          </svg>
        </button>

        {/* Mobile Chat Modal */}
        {isChatOpen && (
          <div className="fixed inset-0 z-50 bg-slate-900 bg-opacity-95">
            <div className="h-full flex flex-col">
              {/* Chat Header */}
              <div className="flex items-center justify-between p-4 border-b border-slate-700">
                <h2 className="text-lg font-semibold">AI Program Discovery</h2>
                <button
                  onClick={() => setIsChatOpen(false)}
                  className="p-2 hover:bg-slate-800 rounded-lg transition-colors"
                  aria-label="Close chat"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              
              {/* Chat Content */}
              <div className="flex-1">
                <ChatInterface />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const StaticContentPanel: React.FC = () => {
  return (
    <div className="p-8 max-w-4xl mx-auto">
      {/* Hero Section */}
      <div className="text-center mb-16">
        <h1 className="text-5xl md:text-6xl font-semibold mb-6 leading-tight tracking-tight">
          Connect Your <span className="text-orange-500">FLL Community</span>
        </h1>
        <p className="text-xl md:text-2xl text-slate-400 mb-8 max-w-3xl mx-auto leading-relaxed">
          Join thousands of families in our FIRST LEGO League community. 
          Find programs, connect with mentors, and build the future together.
        </p>
        
        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <a 
            href="/register" 
            className="px-8 py-3 bg-orange-500 hover:bg-orange-600 rounded-lg font-medium transition-colors duration-200 text-center text-white no-underline"
          >
            Get Started - Register Now
          </a>
          <button className="px-8 py-3 border border-orange-500 text-orange-500 hover:bg-orange-500 hover:text-white rounded-lg font-medium transition-colors duration-200">
            Browse All Programs
          </button>
        </div>
      </div>

      {/* Trust Indicators */}
      <div className="text-center mb-16">
        <p className="text-slate-400 mb-6">Trusted by FLL communities nationwide</p>
        <div className="flex justify-center items-center space-x-8 text-slate-500">
          <div className="text-center">
            <div className="text-2xl font-bold text-white">2,500+</div>
            <div className="text-sm">Active Students</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-white">150+</div>
            <div className="text-sm">Mentor Programs</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-white">95%</div>
            <div className="text-sm">Parent Satisfaction</div>
          </div>
        </div>
      </div>

      {/* Feature Preview */}
      <div className="grid md:grid-cols-2 gap-8 mb-16">
        <FeatureCard 
          icon="🎯"
          title="For Mentors"
          description="Program marketing, team management, progress tracking, and seamless parent communication."
          features={["Create & manage programs", "Track student progress", "Automated communications", "Competition preparation"]}
        />
        <FeatureCard 
          icon="🔍"
          title="For Parents"
          description="Discover programs, compare options, and connect with experienced mentors in your area."
          features={["Location-based search", "Transparent pricing", "Mentor profiles", "Program reviews"]}
        />
      </div>

      {/* Popular Programs Preview */}
      <div className="mb-16">
        <h2 className="text-2xl font-semibold mb-8 text-center">Popular Programs Near You</h2>
        <div className="grid md:grid-cols-3 gap-6">
          <ProgramCard 
            name="Robotics Rockets"
            mentor="Sarah Chen"
            price="$299/season"
            spots="3 spots left"
            rating={4.9}
            image="/api/placeholder/200/150"
          />
          <ProgramCard 
            name="Tech Titans"
            mentor="Mike Rodriguez"
            price="$349/season"
            spots="Open enrollment"
            rating={4.8}
            image="/api/placeholder/200/150"
          />
          <ProgramCard 
            name="LEGO Legends"
            mentor="Emily Watson"
            price="$279/season"
            spots="2 spots left"
            rating={5.0}
            image="/api/placeholder/200/150"
          />
        </div>
      </div>
    </div>
  );
};


interface FeatureCardProps {
  icon: string;
  title: string;
  description: string;
  features: string[];
}

const FeatureCard: React.FC<FeatureCardProps> = ({ icon, title, description, features }) => {
  return (
    <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors">
      <div className="text-3xl mb-4">{icon}</div>
      <h3 className="text-xl font-semibold mb-3">{title}</h3>
      <p className="text-slate-400 mb-4">{description}</p>
      <ul className="space-y-2">
        {features.map((feature, index) => (
          <li key={index} className="flex items-center text-sm text-slate-300">
            <svg className="w-4 h-4 text-orange-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
            </svg>
            {feature}
          </li>
        ))}
      </ul>
    </div>
  );
};

interface ProgramCardProps {
  name: string;
  mentor: string;
  price: string;
  spots: string;
  rating: number;
  image: string;
}

const ProgramCard: React.FC<ProgramCardProps> = ({ name, mentor, price, spots, rating }) => {
  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors overflow-hidden">
      <div className="h-32 bg-slate-700 relative">
        <div className="absolute inset-0 bg-gradient-to-t from-slate-800/50 to-transparent" />
        <div className="absolute bottom-2 left-2 text-xs bg-slate-900/80 px-2 py-1 rounded">
          ⭐ {rating}
        </div>
      </div>
      <div className="p-4">
        <h3 className="font-semibold mb-1">{name}</h3>
        <p className="text-sm text-slate-400 mb-2">Mentor: {mentor}</p>
        <div className="flex justify-between items-center">
          <span className="text-orange-500 font-semibold">{price}</span>
          <span className="text-xs text-slate-400">{spots}</span>
        </div>
      </div>
    </div>
  );
};