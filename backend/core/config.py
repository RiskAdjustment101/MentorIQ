"""
Core configuration for MentorIQ
Security-first settings for COPPA compliance
"""
from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    """Application settings with security defaults"""
    
    # App Info
    app_name: str = "MentorIQ"
    version: str = "0.1.0"
    debug: bool = False
    
    # Security
    secret_key: str = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")
    encryption_key: str = os.environ.get("ENCRYPTION_KEY", "")  # Base64 encoded
    
    # Auth0 Configuration
    auth0_domain: str = os.environ.get("AUTH0_DOMAIN", "")
    auth0_api_audience: str = os.environ.get("AUTH0_API_AUDIENCE", "")
    auth0_client_id: str = os.environ.get("AUTH0_CLIENT_ID", "")
    auth0_client_secret: str = os.environ.get("AUTH0_CLIENT_SECRET", "")
    
    # Database
    database_url: str = os.environ.get("DATABASE_URL", "postgresql://localhost/mentoriq")
    
    # Redis
    redis_url: str = os.environ.get("REDIS_URL", "redis://localhost:6379")
    
    # COPPA Compliance Settings
    minimum_parent_age: int = 18
    child_age_limit: int = 13
    consent_retention_days: int = 7 * 365  # 7 years
    data_deletion_hours: int = 24
    
    # Security Headers
    cors_origins: list = ["http://localhost:3000"]  # Frontend URL
    allowed_hosts: list = ["localhost", "127.0.0.1"]
    
    # Rate Limiting (per IP per minute unless specified)
    rate_limit_auth: str = "5/minute"
    rate_limit_register: str = "3/hour"
    rate_limit_api: str = "100/minute"
    rate_limit_sensitive: str = "10/minute"
    
    # Session Management
    jwt_expiry_minutes: int = 15
    refresh_token_days: int = 7
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    
    # Audit Logging
    audit_retention_days: int = 2555  # 7 years
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Global settings instance
settings = Settings()

# Validation on startup
def validate_security_config():
    """Validate critical security settings"""
    if not settings.encryption_key and not settings.debug:
        raise ValueError("ENCRYPTION_KEY must be set in production")
    
    if not settings.auth0_domain:
        raise ValueError("AUTH0_DOMAIN must be set")
    
    if settings.debug and "prod" in settings.database_url:
        raise ValueError("Debug mode cannot be enabled with production database")
    
    print("✅ Security configuration validated")

# Constitutional AI Principles
CONSTITUTIONAL_AI_PRINCIPLES = {
    "helpful": "Provide genuinely useful guidance for parents and mentors",
    "harmless": "Never recommend actions that could endanger children",
    "honest": "Clearly communicate AI limitations and when human oversight is needed",
    "transparent": "All AI decisions must be explainable to parents",
    "parent_controlled": "Parents can override any AI recommendation",
    "privacy_first": "Minimize data collection, maximize parent control"
}