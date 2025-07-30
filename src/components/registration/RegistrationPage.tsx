import React, { useState } from 'react';
import { RegistrationForm } from './RegistrationForm';
import { RegistrationChat } from './RegistrationChat';

export const RegistrationPage: React.FC = () => {
  const [isChatOpen, setIsChatOpen] = useState(false);

  return (
    <div className="min-h-screen bg-slate-900 text-white font-inter">
      {/* Desktop and Tablet Layout */}
      <div className="hidden md:flex h-screen">
        {/* Registration Form Panel - 70% width */}
        <div className="w-7/10 flex flex-col overflow-y-auto">
          <div className="max-w-2xl mx-auto p-8 w-full">
            <div className="mb-8">
              <h1 className="text-4xl font-semibold mb-4 leading-tight tracking-tight">
                Join the <span className="text-orange-500">MentorIQ</span> Community
              </h1>
              <p className="text-lg text-slate-400 leading-relaxed">
                Whether you're a parent looking for the perfect FLL program or a mentor ready to inspire the next generation, we're here to connect you with amazing opportunities.
              </p>
            </div>
            <RegistrationForm />
          </div>
        </div>
        
        {/* AI Chat Panel - 30% width */}
        <div className="w-3/10 border-l border-slate-700 bg-slate-800">
          <RegistrationChat />
        </div>
      </div>

      {/* Mobile Layout */}
      <div className="md:hidden relative">
        {/* Mobile Form Content */}
        <div className="min-h-screen p-6">
          <div className="mb-8">
            <h1 className="text-3xl font-semibold mb-4 leading-tight tracking-tight">
              Join the <span className="text-orange-500">MentorIQ</span> Community
            </h1>
            <p className="text-slate-400 leading-relaxed">
              Connect with FLL programs and mentors in your area.
            </p>
          </div>
          <RegistrationForm />
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
              <div className="flex items-center justify-between p-4 border-b border-slate-700 bg-slate-800">
                <h2 className="text-lg font-semibold">Registration Assistant</h2>
                <button
                  onClick={() => setIsChatOpen(false)}
                  className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
                  aria-label="Close chat"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              
              {/* Chat Content */}
              <div className="flex-1 bg-slate-800">
                <RegistrationChat />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};