#\!/bin/bash

# MentorIQ Development Startup Script
echo "🚀 Starting MentorIQ S-MVP Development Environment"

# Start backend
echo "🐍 Starting FastAPI backend..."
cd backend
python3 -m venv venv 2>/dev/null || true
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 &

# Start frontend
echo "⚛️  Starting Next.js frontend..."
cd ../frontend
npm install
npm run dev &

echo "✅ Services started\!"
echo "Backend: http://localhost:8000"
echo "Frontend: http://localhost:3000"

# Wait for processes
wait
EOF < /dev/null