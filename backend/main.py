"""
MentorIQ FastAPI Backend with Groq AI Integration
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
import os
from datetime import datetime
import logging

# Initialize Groq
try:
    from groq import Groq
    groq_client = Groq(api_key=os.getenv('GROQ_API_KEY'))
    GROQ_AVAILABLE = True
    logging.info("✅ Groq client initialized")
except Exception as e:
    logging.warning(f"⚠️ Groq not available: {e}")
    groq_client = None
    GROQ_AVAILABLE = False

# Create app
app = FastAPI(title="MentorIQ AI Backend", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for now
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class ChatRequest(BaseModel):
    query: str
    user_context: Optional[Dict] = None
    conversation_history: Optional[List[Dict]] = None

class AIResponse(BaseModel):
    response: str
    context: str
    suggestions: Optional[List[str]] = None
    timestamp: str

# Routes
@app.get("/")
def root():
    return {
        "service": "MentorIQ AI Backend",
        "status": "operational",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "groq_available": GROQ_AVAILABLE,
        "timestamp": datetime.now().isoformat()
    }

async def get_groq_response(query: str, context: str) -> str:
    """Get AI response from Groq"""
    if not GROQ_AVAILABLE:
        return None
    
    try:
        system_prompt = f"""You are an AI assistant for MentorIQ, an AI-augmented mentor platform for FIRST LEGO League programs.

Mission: Transform FIRST LEGO League mentoring through conversational AI, saving mentors 60%+ administrative time.

Context: {context}

Be helpful, encouraging, and knowledgeable about FLL programs. Keep responses conversational but informative (2-3 sentences)."""

        completion = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": query}
            ],
            temperature=0.7,
            max_tokens=300
        )
        
        return completion.choices[0].message.content
    except Exception as e:
        logging.error(f"Groq error: {e}")
        return None

@app.post("/api/ai/chat/landing")
async def landing_chat(request: ChatRequest):
    query = request.query.lower()
    
    # Try Groq first
    ai_response = await get_groq_response(request.query, "landing page program discovery")
    
    # Fallback to pattern matching if Groq fails
    if not ai_response:
        if any(word in query for word in ['parent', 'child', 'kid']):
            ai_response = "Perfect! I'd love to help you find the ideal FLL program for your child. MentorIQ connects families with amazing mentors and teams in your area."
        elif any(word in query for word in ['mentor', 'teach', 'coach']):
            ai_response = "Wonderful! We're excited to connect with passionate educators. MentorIQ saves mentors 60%+ of administrative time through AI-powered tools."
        else:
            ai_response = "Welcome to MentorIQ! I'm here to help you discover amazing FLL programs and mentors. What brings you here today?"
    
    # Generate suggestions based on query
    if any(word in query for word in ['parent', 'child']):
        suggestions = ["Tell me about program costs", "How do I evaluate mentors?", "Take me to registration"]
    elif any(word in query for word in ['mentor', 'teach']):
        suggestions = ["How does the platform save time?", "What support do mentors get?", "Create my mentor profile"]
    else:
        suggestions = ["I'm a parent looking for programs", "I want to become a mentor", "Tell me about your platform"]
    
    return {
        "response": ai_response,
        "context": "landing",
        "suggestions": suggestions,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/ai/chat/registration")
def registration_chat(request: ChatRequest):
    query = request.query
    
    # Extract basic info
    field_updates = {}
    response = "I'm here to help you complete your registration! "
    
    # Simple name detection
    if "name is" in query.lower() or "i'm" in query.lower():
        words = query.split()
        for i, word in enumerate(words):
            if word.lower() in ["name", "i'm", "am"] and i + 1 < len(words):
                potential_name = words[i + 1].strip(".,!?")
                if potential_name.isalpha():
                    field_updates["name"] = potential_name
                    response = f"Hi {potential_name}! Great to meet you. "
                break
    
    # Simple email detection
    if "@" in query:
        words = query.split()
        for word in words:
            if "@" in word and "." in word:
                field_updates["email"] = word.strip(".,!?")
                response += "Thanks for providing your email address! "
                break
    
    # User type detection
    if any(word in query.lower() for word in ['parent', 'child', 'kid']):
        field_updates["userType"] = "parent"
        response += "Wonderful! We're excited to help you find the perfect FLL program for your child."
    elif any(word in query.lower() for word in ['mentor', 'teach', 'coach']):
        field_updates["userType"] = "mentor"
        response += "Fantastic! We need more passionate mentors like you."
    
    if not field_updates:
        response = "I'm here to help you complete your registration! You can tell me your name, email, and whether you're a parent or mentor."
    
    return {
        "response": response,
        "context": "registration", 
        "field_updates": field_updates,
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)