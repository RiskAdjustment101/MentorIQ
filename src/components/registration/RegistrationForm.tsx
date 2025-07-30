import React from 'react';
import { useRegistrationStore, UserType } from '../../stores/registrationStore';

export const RegistrationForm: React.FC = () => {
  const {
    registrationData,
    completionStatus,
    activeField,
    updateField,
    setActiveField,
    addMessage,
    updateInteractionTime,
  } = useRegistrationStore();

  // Handle form field changes and sync with chat
  const handleFieldChange = (field: keyof typeof registrationData, value: string | UserType | null) => {
    updateField(field, value);
    updateInteractionTime();
    
    // Add contextual AI response based on field update
    if (field === 'name' && typeof value === 'string' && value.trim()) {
      setTimeout(() => {
        addMessage({
          content: `Hi ${value}! I see you're getting started with your registration. That's great!`,
          sender: 'ai',
          triggeredField: 'name',
        });
      }, 500);
    } else if (field === 'email' && typeof value === 'string' && value.includes('@')) {
      setTimeout(() => {
        const domain = value.split('@')[1];
        let response = `Thanks for providing your email address!`;
        
        // Contextual responses based on email domain
        if (domain?.includes('edu')) {
          response += ` I see you're from an educational institution - that's wonderful! Many of our best mentors come from educational backgrounds.`;
        } else if (domain?.includes('gmail') || domain?.includes('yahoo') || domain?.includes('hotmail')) {
          response += ` I've got your contact information saved.`;
        } else {
          response += ` Great to have you joining from ${domain}!`;
        }
        
        addMessage({
          content: response,
          sender: 'ai',
          triggeredField: 'email',
        });
      }, 500);
    } else if (field === 'userType' && value) {
      setTimeout(() => {
        const responses = {
          parent: "Wonderful! We're excited to help you find the perfect FLL program for your child. Our platform connects families with amazing mentors and teams in your area.",
          mentor: "Fantastic! We need more passionate mentors like you. Whether you're looking to start a new team or join an existing program, we'll help you make a real impact on students' lives.",
        };
        
        addMessage({
          content: responses[value as UserType],
          sender: 'ai',
          triggeredField: 'userType',
        });
      }, 500);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!completionStatus.name || !completionStatus.email || !completionStatus.userType) {
      addMessage({
        content: "Please make sure to fill in all required fields before submitting.",
        sender: 'ai',
      });
      return;
    }

    // Handle successful registration
    addMessage({
      content: `Perfect! Your registration is complete, ${registrationData.name}. Welcome to the MentorIQ community! You'll receive a confirmation email shortly.`,
      sender: 'ai',
    });
    
    // Here you would typically send the data to your backend
    console.log('Registration submitted:', registrationData);
  };

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-8">
      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Name Field */}
        <div className="space-y-2">
          <label htmlFor="name" className="block text-sm font-medium text-slate-200">
            Full Name *
          </label>
          <input
            type="text"
            id="name"
            value={registrationData.name}
            onChange={(e) => handleFieldChange('name', e.target.value)}
            onFocus={() => setActiveField('name')}
            onBlur={() => setActiveField(null)}
            className={`w-full px-4 py-3 bg-slate-700 border rounded-lg text-white placeholder-slate-400 transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent ${
              activeField === 'name' ? 'border-orange-500' : 'border-slate-600'
            } ${completionStatus.name ? 'border-green-500' : ''}`}
            placeholder="Enter your full name"
            required
          />
          {completionStatus.name && (
            <div className="flex items-center text-green-400 text-sm">
              <svg className="w-4 h-4 mr-1" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
              </svg>
              Looks good!
            </div>
          )}
        </div>

        {/* Email Field */}
        <div className="space-y-2">
          <label htmlFor="email" className="block text-sm font-medium text-slate-200">
            Email Address *
          </label>
          <input
            type="email"
            id="email"
            value={registrationData.email}
            onChange={(e) => handleFieldChange('email', e.target.value)}
            onFocus={() => setActiveField('email')}
            onBlur={() => setActiveField(null)}
            className={`w-full px-4 py-3 bg-slate-700 border rounded-lg text-white placeholder-slate-400 transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent ${
              activeField === 'email' ? 'border-orange-500' : 'border-slate-600'
            } ${completionStatus.email ? 'border-green-500' : ''}`}
            placeholder="Enter your email address"
            required
          />
          {completionStatus.email && (
            <div className="flex items-center text-green-400 text-sm">
              <svg className="w-4 h-4 mr-1" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
              </svg>
              Valid email format
            </div>
          )}
        </div>

        {/* User Type Field */}
        <div className="space-y-3">
          <label className="block text-sm font-medium text-slate-200">
            I am a... *
          </label>
          <div className="space-y-3">
            <label className="flex items-center space-x-3 cursor-pointer">
              <input
                type="radio"
                name="userType"
                value="parent"
                checked={registrationData.userType === 'parent'}
                onChange={(e) => handleFieldChange('userType', e.target.value as UserType)}
                className="w-4 h-4 text-orange-500 bg-slate-700 border-slate-600 focus:ring-orange-500 focus:ring-2"
              />
              <div>
                <div className="text-white font-medium">Parent</div>
                <div className="text-sm text-slate-400">Looking for FLL programs for my child</div>
              </div>
            </label>
            
            <label className="flex items-center space-x-3 cursor-pointer">
              <input
                type="radio"
                name="userType"
                value="mentor"
                checked={registrationData.userType === 'mentor'}
                onChange={(e) => handleFieldChange('userType', e.target.value as UserType)}
                className="w-4 h-4 text-orange-500 bg-slate-700 border-slate-600 focus:ring-orange-500 focus:ring-2"
              />
              <div>
                <div className="text-white font-medium">Mentor</div>
                <div className="text-sm text-slate-400">Want to lead or assist with FLL teams</div>
              </div>
            </label>
          </div>
          {completionStatus.userType && (
            <div className="flex items-center text-green-400 text-sm">
              <svg className="w-4 h-4 mr-1" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
              </svg>
              Great choice!
            </div>
          )}
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={!completionStatus.name || !completionStatus.email || !completionStatus.userType}
          className={`w-full px-6 py-3 rounded-lg font-medium transition-colors duration-200 ${
            completionStatus.name && completionStatus.email && completionStatus.userType
              ? 'bg-orange-500 hover:bg-orange-600 text-white'
              : 'bg-slate-600 text-slate-400 cursor-not-allowed'
          }`}
        >
          {completionStatus.name && completionStatus.email && completionStatus.userType
            ? 'Complete Registration'
            : 'Please fill in all fields'}
        </button>

        {/* Progress Indicator */}
        <div className="mt-6">
          <div className="flex justify-between text-sm text-slate-400 mb-2">
            <span>Registration Progress</span>
            <span>
              {Object.values(completionStatus).filter(Boolean).length} of 3 completed
            </span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-orange-500 h-2 rounded-full transition-all duration-300"
              style={{
                width: `${(Object.values(completionStatus).filter(Boolean).length / 3) * 100}%`,
              }}
            />
          </div>
        </div>
      </form>
    </div>
  );
};