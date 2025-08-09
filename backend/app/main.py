"""
MentorIQ FastAPI Application
COPPA-compliant, parent-controlled mentoring platform
"""
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn
from datetime import datetime

from backend.core.config import settings, validate_security_config, CONSTITUTIONAL_AI_PRINCIPLES
from backend.security.auth import require_parent, get_current_parent_id

# Initialize security
security = HTTPBearer()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events"""
    # Startup
    print("🚀 Starting MentorIQ API...")
    
    # Validate security configuration
    validate_security_config()
    
    # Test encryption service
    from backend.security.encryption import test_encryption
    test_encryption()
    
    print("✅ Security services initialized")
    print("✅ Constitutional AI principles loaded:")
    for principle, description in CONSTITUTIONAL_AI_PRINCIPLES.items():
        print(f"   • {principle}: {description}")
    
    yield
    
    # Shutdown
    print("🛑 Shutting down MentorIQ API...")

# Create FastAPI application
app = FastAPI(
    title="MentorIQ API",
    description="COPPA-compliant AI-powered mentoring platform for parents and FLL teams",
    version=settings.version,
    docs_url="/docs" if settings.debug else None,  # Disable docs in production
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)

# Security Middleware
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=settings.allowed_hosts
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-RateLimit-Remaining", "X-RateLimit-Reset"]
)

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    # Security headers for COPPA compliance and safety
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    
    # Content Security Policy
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.auth0.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://*.auth0.com; "
        "frame-ancestors 'none';"
    )
    response.headers["Content-Security-Policy"] = csp
    
    return response

# Health Check Endpoints
@app.get("/health")
async def health_check():
    """Basic health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": settings.version
    }

@app.get("/health/ready")
async def readiness_check():
    """Readiness check with dependency validation"""
    try:
        # Test Auth0 connection
        from backend.security.auth import verify_auth0_connection
        auth0_ready = await verify_auth0_connection()
        
        # Test encryption
        from backend.security.encryption import test_encryption
        encryption_ready = test_encryption()
        
        if not auth0_ready:
            raise HTTPException(status_code=503, detail="Auth0 service unavailable")
        
        if not encryption_ready:
            raise HTTPException(status_code=503, detail="Encryption service unavailable")
        
        return {
            "status": "ready",
            "services": {
                "auth0": "healthy",
                "encryption": "healthy",
                "database": "pending"  # Will add after DB setup
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service not ready: {str(e)}")

# Parent Authentication Endpoints
@app.get("/api/parent/profile")
async def get_parent_profile(parent_id: str = Depends(get_current_parent_id)):
    """
    Get parent profile information
    All PII is decrypted only for the owning parent
    """
    # This would fetch from database and decrypt PII
    return {
        "parent_id": parent_id,
        "message": "Parent profile endpoint - to be implemented with database",
        "note": "All PII will be encrypted in database and decrypted for parent only"
    }

@app.get("/api/parent/children")
async def get_parent_children(parent_id: str = Depends(get_current_parent_id)):
    """
    Get all children profiles for the authenticated parent
    COPPA compliance: Parent controls all child data
    """
    # This would fetch children from database
    return {
        "parent_id": parent_id,
        "children": [],  # Will populate from database
        "message": "Child profiles controlled by parent - COPPA compliant"
    }

@app.post("/api/parent/child")
async def create_child_profile(
    child_data: dict,
    parent_id: str = Depends(get_current_parent_id)
):
    """
    Create child profile (parent-controlled)
    NO direct child access - parent creates and manages
    """
    # Validate child data doesn't contain PII
    allowed_fields = {"display_name", "age_bracket", "interests"}
    
    if not set(child_data.keys()).issubset(allowed_fields):
        raise HTTPException(
            status_code=400,
            detail=f"Only allowed fields: {allowed_fields}"
        )
    
    # Validate age bracket
    if child_data.get("age_bracket") not in ["8-10", "11-13"]:
        raise HTTPException(
            status_code=400,
            detail="Age bracket must be '8-10' or '11-13'"
        )
    
    return {
        "message": "Child profile created successfully",
        "parent_id": parent_id,
        "child_data": child_data,
        "note": "Profile linked to parent - COPPA compliant"
    }

# COPPA Information Endpoint (Public)
@app.get("/api/coppa-info")
async def coppa_information():
    """
    Public COPPA compliance information
    Required for transparency
    """
    return {
        "title": "Children's Privacy Protection",
        "summary": "MentorIQ is designed with children's safety as our top priority",
        "key_points": [
            "Children cannot create accounts - only parents/guardians can",
            "All child profiles are created and controlled by verified parents",
            "No personal information is collected directly from children",
            "Parents have complete control over their child's data",
            "Data can be deleted at any time upon parent request",
            "All communications are monitored by AI for safety"
        ],
        "compliance": {
            "regulation": "COPPA (Children's Online Privacy Protection Act)",
            "age_limit": 13,
            "parent_consent": "Required for all child-related data",
            "data_retention": "Controlled by parent preferences"
        },
        "contact": "privacy@mentoriq.com"
    }

# Constitutional AI Information
@app.get("/api/ai-principles")
async def constitutional_ai_principles():
    """
    Public information about our AI safety principles
    Transparency for parents about AI decision-making
    """
    return {
        "title": "Constitutional AI Principles",
        "description": "Our AI follows strict safety and ethical guidelines",
        "principles": CONSTITUTIONAL_AI_PRINCIPLES,
        "safety_measures": [
            "All AI interactions are monitored for safety",
            "Parents can view and override any AI recommendation", 
            "AI explanations are provided in parent-friendly language",
            "Emergency human oversight is always available",
            "Content filtering prevents inappropriate material"
        ],
        "transparency": "All AI decisions include explanations of reasoning"
    }

# Error Handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Handle 404 errors with security considerations"""
    return {
        "error": "Endpoint not found",
        "message": "Please check the API documentation",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    """Handle 500 errors without exposing sensitive information"""
    return {
        "error": "Internal server error",
        "message": "An error occurred. If this persists, please contact support.",
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": "placeholder-for-request-tracking"
    }

if __name__ == "__main__":
    # Development server
    uvicorn.run(
        "backend.app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=settings.debug,
        log_level="info"
    )