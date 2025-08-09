"""
Auth0 JWT validation and authentication service
COPPA-compliant parent authentication only
"""
from fastapi import Depends, HTTPException, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
import httpx
from functools import lru_cache
from typing import Optional, Dict, Any
import hashlib
from datetime import datetime, timedelta
import asyncio

from backend.core.config import settings

security = HTTPBearer()

class Auth0Service:
    """
    Auth0 integration service with COPPA compliance
    Validates JWTs and ensures parent-only access
    """
    
    def __init__(self):
        self.domain = settings.auth0_domain
        self.api_audience = settings.auth0_api_audience
        self.algorithms = ['RS256']
        self._jwks_cache = None
        self._jwks_cache_time = None
        self.cache_duration = timedelta(hours=1)
    
    async def get_jwks(self) -> Dict[str, Any]:
        """
        Get Auth0 public keys with caching
        Cached for 1 hour for performance
        """
        now = datetime.utcnow()
        
        if (self._jwks_cache is None or 
            self._jwks_cache_time is None or
            now - self._jwks_cache_time > self.cache_duration):
            
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        f'https://{self.domain}/.well-known/jwks.json',
                        timeout=5.0
                    )
                    response.raise_for_status()
                    
                self._jwks_cache = response.json()
                self._jwks_cache_time = now
                
            except Exception as e:
                if self._jwks_cache is None:
                    raise HTTPException(
                        status_code=503,
                        detail="Authentication service unavailable"
                    )
                # Use cached version if available
                print(f"⚠️ JWKS refresh failed, using cache: {e}")
        
        return self._jwks_cache
    
    async def verify_token(
        self, 
        credentials: HTTPAuthorizationCredentials = Security(security)
    ) -> Dict[str, Any]:
        """
        Verify Auth0 JWT token and extract claims
        Enforces parent role requirement
        """
        token = credentials.credentials
        
        try:
            # Get unverified header to find key ID
            unverified_header = jwt.get_unverified_header(token)
            
            # Get JWKS and find matching key
            jwks = await self.get_jwks()
            
            rsa_key = {}
            for key in jwks.get("keys", []):
                if key["kid"] == unverified_header["kid"]:
                    rsa_key = {
                        "kty": key["kty"],
                        "kid": key["kid"],
                        "use": key["use"],
                        "n": key["n"],
                        "e": key["e"]
                    }
                    break
            
            if not rsa_key:
                raise HTTPException(
                    status_code=401,
                    detail="Unable to find appropriate signing key"
                )
            
            # Verify and decode token
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=self.algorithms,
                audience=self.api_audience,
                issuer=f'https://{self.domain}/'
            )
            
            # COPPA Compliance: Verify parent role
            role = payload.get('https://mentoriq.com/role')
            if role != 'parent':
                await self._log_unauthorized_access(payload, "non_parent_role")
                raise HTTPException(
                    status_code=403,
                    detail="Parent role required. Children cannot access this system."
                )
            
            # Verify email verification status
            email_verified = payload.get('email_verified', False)
            if not email_verified:
                raise HTTPException(
                    status_code=403,
                    detail="Email verification required"
                )
            
            # Check token expiration (additional safety)
            exp = payload.get('exp')
            if exp and datetime.utcnow().timestamp() > exp:
                raise HTTPException(
                    status_code=401,
                    detail="Token has expired"
                )
            
            return payload
            
        except JWTError as e:
            await self._log_auth_failure("jwt_error", str(e))
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token"
            )
        except HTTPException:
            # Re-raise HTTP exceptions as-is
            raise
        except Exception as e:
            await self._log_auth_failure("unexpected_error", str(e))
            raise HTTPException(
                status_code=500,
                detail="Authentication verification failed"
            )
    
    async def verify_mentor_token(
        self,
        credentials: HTTPAuthorizationCredentials = Security(security)
    ) -> Dict[str, Any]:
        """
        Verify mentor JWT token
        Requires mentor role and admin verification
        """
        token_data = await self.verify_token(credentials)
        
        # Check mentor role
        role = token_data.get('https://mentoriq.com/role')
        if role != 'mentor':
            raise HTTPException(
                status_code=403,
                detail="Mentor role required"
            )
        
        # Check admin verification status
        verified = token_data.get('https://mentoriq.com/verified', False)
        if not verified:
            raise HTTPException(
                status_code=403,
                detail="Admin verification required for mentors"
            )
        
        return token_data
    
    async def _log_unauthorized_access(self, payload: dict, reason: str):
        """Log unauthorized access attempts for security monitoring"""
        try:
            # Hash the subject for audit trail (no PII in logs)
            subject_hash = hashlib.sha256(
                payload.get('sub', '').encode()
            ).hexdigest()
            
            audit_data = {
                "action": "unauthorized_access_attempt",
                "reason": reason,
                "subject_hash": subject_hash,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # In production, send to security monitoring service
            print(f"🚨 Security Alert: {audit_data}")
            
        except Exception as e:
            print(f"⚠️ Audit logging failed: {e}")
    
    async def _log_auth_failure(self, failure_type: str, details: str):
        """Log authentication failures for monitoring"""
        try:
            audit_data = {
                "action": "authentication_failure",
                "failure_type": failure_type,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            print(f"🚨 Auth Failure: {audit_data}")
            
        except Exception as e:
            print(f"⚠️ Audit logging failed: {e}")

# Global service instance
auth0_service = Auth0Service()

# Dependency functions for FastAPI routes
async def require_parent(
    token_data: dict = Depends(auth0_service.verify_token)
) -> dict:
    """
    Dependency that requires authenticated parent
    Use this on all parent-only endpoints
    """
    return token_data

async def require_mentor(
    token_data: dict = Depends(auth0_service.verify_mentor_token)
) -> dict:
    """
    Dependency that requires verified mentor
    Use this on mentor-only endpoints
    """
    return token_data

async def get_current_parent_id(
    token_data: dict = Depends(require_parent)
) -> str:
    """Get the current parent's Auth0 ID from token"""
    return token_data['sub']

async def get_current_mentor_id(
    token_data: dict = Depends(require_mentor)
) -> str:
    """Get the current mentor's Auth0 ID from token"""
    return token_data['sub']

# Rate limiting decorator for sensitive operations
def rate_limit_sensitive(func):
    """Apply sensitive operation rate limiting"""
    # This would integrate with Redis-based rate limiting
    # For now, placeholder for implementation
    return func

# Optional: Extract user info safely
def extract_safe_user_info(token_data: dict) -> dict:
    """
    Extract non-PII user information from token
    Safe for logging and audit trails
    """
    return {
        "subject_hash": hashlib.sha256(token_data['sub'].encode()).hexdigest(),
        "role": token_data.get('https://mentoriq.com/role'),
        "verified": token_data.get('https://mentoriq.com/verified', False),
        "issued_at": token_data.get('iat'),
        "expires_at": token_data.get('exp')
    }

# Health check function
async def verify_auth0_connection() -> bool:
    """
    Verify Auth0 connection is working
    Used for health checks
    """
    try:
        service = Auth0Service()
        jwks = await service.get_jwks()
        return len(jwks.get('keys', [])) > 0
    except Exception:
        return False