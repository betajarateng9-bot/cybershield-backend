from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship

from datetime import datetime

from .database import Base


class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String(100), nullable=False)

    phone = Column(String(30), nullable=False)

    email = Column(String(150), nullable=False)

    organization = Column(String(150), nullable=True)

    service = Column(String(100), nullable=False)

    message = Column(Text, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    status = Column(String(30), default="new")

class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, index=True)

    full_name = Column(String(100), nullable=False)

    email = Column(String(150), nullable=False, unique=True, index=True)

    phone = Column(String(30), nullable=False)

    organization = Column(String(150), nullable=True)

    industry = Column(String(100), nullable=True)
    address = Column(String(255), nullable=True)

    notes = Column(Text, nullable=True)

    status = Column(String(30), default="active")  # active / inactive

    created_at = Column(DateTime, default=datetime.utcnow)
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class User(Base):
     __tablename__ = "users"

     id = Column(Integer, primary_key=True, index=True)

     email = Column(String(150), nullable=False, unique=True, index=True)
     hashed_password = Column(String(255), nullable=False)
 
     role = Column(String(20), nullable=False, default="customer")

     customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
     customer = relationship("Customer", backref="user_account")

     is_active = Column(Boolean, default=True)
     created_at = Column(DateTime, default=datetime.utcnow)

     failed_login_attempts = Column(Integer, default=0)
     locked_until = Column(DateTime, nullable=True)
     

class ServiceRequest(Base):
    __tablename__ = "service_requests"

    id = Column(Integer, primary_key=True, index=True)

    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    customer = relationship("Customer", backref="service_requests")

    request_type = Column(String(50), nullable=False)  # "service", "security_assessment", "support_ticket"
    subject = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)

    status = Column(String(30), default="open")  # open / in progress / resolved / closed
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)

    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    customer = relationship("Customer", backref="assets")

    name = Column(String(150), nullable=False)
    target = Column(String(255), nullable=False)

    scan_frequency = Column(String(20), default="disabled")  # disabled / every_5_min / daily / weekly
    last_scanned_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)

    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    asset = relationship("Asset", backref="scan_results")

    status = Column(String(30), default="completed")  # completed / failed
    open_ports_count = Column(Integer, default=0)
    highest_risk = Column(String(20), default="none")  # none / low / medium / high

    scanned_at = Column(DateTime, default=datetime.utcnow)


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id = Column(Integer, primary_key=True, index=True)

    scan_result_id = Column(Integer, ForeignKey("scan_results.id"), nullable=False)
    scan_result = relationship("ScanResult", backref="findings")

    port = Column(Integer, nullable=False)
    service = Column(String(50), nullable=False)
    risk_level = Column(String(20), nullable=False)  # low / medium / high
    description = Column(Text, nullable=True) 

    
class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)

    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    asset = relationship("Asset", backref="alerts")

    scan_result_id = Column(Integer, ForeignKey("scan_results.id"), nullable=False)

    message = Column(Text, nullable=False)
    risk_level = Column(String(20), nullable=False)
    is_acknowledged = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User")

    action = Column(String(100), nullable=False)  # e.g. "delete_customer", "run_scan"
    target_type = Column(String(50), nullable=True)  # e.g. "customer", "asset"
    target_id = Column(Integer, nullable=True)
    details = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    
class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(36), unique=True, nullable=False, index=True)
    revoked_at = Column(DateTime, default=datetime.utcnow)