#!/bin/bash

# MentorIQ Development Startup Script
# Starts both backend and frontend in development mode

echo "🚀 Starting MentorIQ S-MVP Development Environment"
echo "=============================================="

# Check if virtual environment exists
if [ ! -d "backend/venv" ]; then
    echo "📦 Creating Python virtual environment..."
    cd backend
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    cd ..
    echo "✅ Backend dependencies installed"
else
    echo "✅ Backend virtual environment exists"
fi

# Check if node_modules exists
if [ ! -d "frontend/node_modules" ]; then
    echo "📦 Installing frontend dependencies..."
    cd frontend
    npm install
    cd ..
    echo "✅ Frontend dependencies installed"
else
    echo "✅ Frontend dependencies exist"
fi

# Generate encryption key if not exists
if [ ! -f "backend/.env" ]; then
    echo "🔑 Generating security configuration..."
    
    # Generate encryption key
    ENCRYPTION_KEY=$(python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; import base64; print(base64.b64encode(AESGCM.generate_key(256)).decode())")
    
    # Generate Auth0 secret
    AUTH0_SECRET=$(openssl rand -hex 32)
    
    # Create backend .env
    cp backend/.env.template backend/.env
    sed -i '' "s/base64-encoded-256-bit-key-here/$ENCRYPTION_KEY/" backend/.env
    
    # Create frontend .env.local
    cp frontend/.env.local.template frontend/.env.local
    sed -i '' "s/use-openssl-rand-hex-32-to-generate-this/$AUTH0_SECRET/" frontend/.env.local
    
    echo "⚠️  IMPORTANT: Configure Auth0 settings in:"
    echo "   - backend/.env"
    echo "   - frontend/.env.local"
    echo ""
fi

# Start services
echo "🔧 Starting development servers..."
echo ""
echo "Backend will start on: http://localhost:8000"
echo "Frontend will start on: http://localhost:3000"
echo "API Docs will be at: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Function to kill all background processes on exit
cleanup() {
    echo ""
    echo "🛑 Stopping all services..."
    kill $(jobs -p) 2>/dev/null
    exit
}

# Set up cleanup trap
trap cleanup INT TERM

# Start backend
echo "🐍 Starting FastAPI backend..."
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!
cd ..

# Wait a moment for backend to start
sleep 3

# Start frontend
echo "⚛️  Starting Next.js frontend..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

# Wait for both processes
wait $BACKEND_PID $FRONTEND_PID