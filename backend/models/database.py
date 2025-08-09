"""
Database models for MentorIQ
COPPA-compliant schema with encrypted PII fields
"""
from sqlalchemy import Column, String, Boolean, DateTime, Text, ForeignKey, Integer, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from datetime import datetime

Base = declarative_base()

class Parent(Base):
    """
    Parent/Guardian accounts - the only account holders
    All PII fields are encrypted before storage
    """
    __tablename__ = "parents"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Auth0 integration
    auth0_id = Column(String(255), unique=True, nullable=False, index=True)
    
    # Encrypted PII fields (never stored in plaintext)
    email_encrypted = Column(Text, nullable=False)  # Encrypted email
    name_encrypted = Column(Text, nullable=False)   # Encrypted full name
    phone_encrypted = Column(Text, nullable=True)   # Encrypted phone (optional)
    
    # Account status
    verified = Column(Boolean, default=False, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    
    # Verification
    verification_token_hash = Column(String(255), nullable=True)
    verification_expires = Column(DateTime, nullable=True)
    
    # COPPA consent tracking
    consent_timestamp = Column(DateTime, nullable=False, default=func.now())
    consent_ip_encrypted = Column(Text, nullable=True)  # Encrypted IP for consent
    terms_version = Column(String(50), nullable=False, default="1.0")
    coppa_consent = Column(Boolean, nullable=False, default=False)
    
    # Security
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    password_reset_token = Column(String(255), nullable=True)
    password_reset_expires = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    children = relationship("Child", back_populates="parent", cascade="all, delete-orphan")
    audit_entries = relationship("AuditLog", back_populates="parent")
    
    def __repr__(self):
        return f"<Parent(id={self.id}, verified={self.verified})>"

class Child(Base):
    """
    Child profiles - always linked to parent
    NO direct authentication, NO PII collection
    """
    __tablename__ = "children"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Parent relationship (required)
    parent_id = Column(UUID(as_uuid=True), ForeignKey("parents.id"), nullable=False)
    
    # Non-PII identifiers
    display_name = Column(String(50), nullable=False)  # Nickname only
    age_bracket = Column(String(20), nullable=False)   # "8-10", "11-13" (not exact age)
    
    # Preferences (encrypted as may contain indirect identifiers)
    interests_encrypted = Column(Text, nullable=True)     # JSON encrypted
    preferences_encrypted = Column(Text, nullable=True)   # JSON encrypted
    goals_encrypted = Column(Text, nullable=True)         # JSON encrypted
    
    # Profile status
    active = Column(Boolean, default=True, nullable=False)
    mentor_approved = Column(Boolean, default=False, nullable=False)  # Parent approval for mentoring
    
    # Timestamps
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    
    # Relationships
    parent = relationship("Parent", back_populates="children")
    mentoring_sessions = relationship("MentoringSession", back_populates="child")
    
    def __repr__(self):
        return f"<Child(id={self.id}, display_name={self.display_name}, parent_id={self.parent_id})>"

class Mentor(Base):
    """
    Verified mentors with background checks
    All PII encrypted, admin verification required
    """
    __tablename__ = "mentors"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Auth0 integration
    auth0_id = Column(String(255), unique=True, nullable=False, index=True)
    
    # Encrypted PII
    email_encrypted = Column(Text, nullable=False)
    name_encrypted = Column(Text, nullable=False)
    phone_encrypted = Column(Text, nullable=True)
    
    # Verification status
    background_check_status = Column(String(50), default="pending")  # pending, approved, rejected
    background_check_date = Column(DateTime, nullable=True)
    verified_by_admin = Column(Boolean, default=False, nullable=False)
    
    # Professional info (non-PII)
    expertise_areas = Column(JSON, nullable=True)  # ["robotics", "programming"]
    experience_years = Column(Integer, nullable=True)
    availability = Column(JSON, nullable=True)  # Time slots
    
    # Status
    active = Column(Boolean, default=True, nullable=False)
    accepting_new_students = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    mentoring_sessions = relationship("MentoringSession", back_populates="mentor")
    
    def __repr__(self):
        return f"<Mentor(id={self.id}, verified={self.verified_by_admin})>"

class MentoringSession(Base):
    """
    Mentoring sessions with safety monitoring
    Parent oversight required
    """
    __tablename__ = "mentoring_sessions"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Relationships
    child_id = Column(UUID(as_uuid=True), ForeignKey("children.id"), nullable=False)
    mentor_id = Column(UUID(as_uuid=True), ForeignKey("mentors.id"), nullable=False)
    
    # Session details
    scheduled_start = Column(DateTime, nullable=False)
    scheduled_end = Column(DateTime, nullable=False)
    actual_start = Column(DateTime, nullable=True)
    actual_end = Column(DateTime, nullable=True)
    
    # Status
    status = Column(String(50), default="scheduled")  # scheduled, in_progress, completed, cancelled
    parent_approved = Column(Boolean, default=False, nullable=False)
    
    # Safety monitoring
    safety_flags = Column(JSON, nullable=True)  # AI safety alerts
    parent_notes = Column(Text, nullable=True)
    mentor_notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    
    # Relationships
    child = relationship("Child", back_populates="mentoring_sessions")
    mentor = relationship("Mentor", back_populates="mentoring_sessions")
    
    def __repr__(self):
        return f"<Session(id={self.id}, status={self.status})>"

class AuditLog(Base):
    """
    Audit trail for compliance
    NO PII EVER stored in audit logs
    """
    __tablename__ = "audit_logs"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Action details
    action = Column(String(100), nullable=False)  # "parent_login", "child_created"
    actor_type = Column(String(20), nullable=False)  # "parent", "mentor", "admin", "system"
    actor_id_hash = Column(String(255), nullable=True)  # SHA-256 hash only
    
    # Context (NO PII)
    resource_type = Column(String(50), nullable=True)  # "child_profile", "session"
    resource_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Metadata (sanitized)
    metadata = Column(JSON, nullable=True)  # Non-PII context only
    ip_address_hash = Column(String(255), nullable=True)  # Hashed IP
    user_agent_hash = Column(String(255), nullable=True)  # Hashed user agent
    
    # Results
    success = Column(Boolean, nullable=False, default=True)
    error_code = Column(String(50), nullable=True)
    
    # Timestamp
    timestamp = Column(DateTime, nullable=False, default=func.now(), index=True)
    
    # Optional parent reference (for filtering)
    parent_id = Column(UUID(as_uuid=True), ForeignKey("parents.id"), nullable=True)
    parent = relationship("Parent", back_populates="audit_entries")
    
    def __repr__(self):
        return f"<AuditLog(action={self.action}, timestamp={self.timestamp})>"

class DataDeletionRequest(Base):
    """
    Track COPPA data deletion requests
    Required for compliance
    """
    __tablename__ = "data_deletion_requests"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Request details
    parent_id = Column(UUID(as_uuid=True), ForeignKey("parents.id"), nullable=False)
    request_type = Column(String(50), nullable=False)  # "full_deletion", "child_only"
    reason = Column(String(200), nullable=True)
    
    # Status
    status = Column(String(50), default="pending")  # pending, in_progress, completed, failed
    requested_at = Column(DateTime, nullable=False, default=func.now())
    completed_at = Column(DateTime, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    
    # Data retention (for legal requirements)
    retention_end_date = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<DeletionRequest(id={self.id}, status={self.status})>"