import logging

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy.orm import Session
from datetime import datetime

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .database import engine, Base, get_db
from . import models
from . import security
from . import deps
from . import scanner

from . import scheduled_scans
from . import audit

from fastapi.security import HTTPAuthorizationCredentials
from .deps import bearer_scheme

from datetime import datetime, timedelta


# ==================================================
# LOGGING
# ==================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cybershield")


# ==================================================
# APPLICATION
# ==================================================

app = FastAPI(
    title="CyberShield API",
    description="CyberShield Cybersecurity Platform API",
    version="1.0.0"
)


# ==================================================
# RATE LIMITING
# ==================================================

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ==================================================
# DATABASE
# ==================================================

Base.metadata.create_all(bind=engine)

scheduler = scheduled_scans.start_scheduler()

# ==================================================
# CORS
# ==================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
        "https://cybershieldbeta.netlify.app/"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================================================
# GLOBAL EXCEPTION HANDLER
# ==================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. Please try again later."}
    )


# ==========================================================
# ==========================================================
#   DATA MODELS (SCHEMAS) — all grouped together
# ==========================================================
# ==========================================================


# ==================================================
# CONTACT SCHEMAS
# ==================================================

class ContactMessage(BaseModel):
    name: str
    phone: str
    email: str
    organization: str
    service: str
    message: str


class ContactResponse(BaseModel):
    id: int
    name: str
    phone: str
    email: str
    organization: str | None
    service: str | None
    message: str
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ContactStatusUpdate(BaseModel):
    status: str


# ==================================================
# CUSTOMER SCHEMAS
# ==================================================

class CustomerCreate(BaseModel):
    full_name: str
    email: str
    phone: str
    organization: str | None = None
    industry: str | None = None
    address: str | None = None
    notes: str | None = None


class CustomerUpdate(BaseModel):
    full_name: str | None = None
    email: str | None = None
    phone: str | None = None
    organization: str | None = None
    industry: str | None = None
    address: str | None = None
    notes: str | None = None
    status: str | None = None


class CustomerResponse(BaseModel):
    id: int
    full_name: str
    email: str
    phone: str
    organization: str | None
    industry: str | None
    address: str | None
    notes: str | None
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CustomerRegister(BaseModel):
    full_name: str
    email: str
    phone: str
    organization: str | None = None
    industry: str | None = None
    address: str | None = None
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


# ==================================================
# USER ACCOUNT SCHEMAS
# ==================================================

class UserCreate(BaseModel):
    email: str
    password: str
    role: str = "customer"
    customer_id: int | None = None

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    customer_id: int | None
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==================================================
# LOGIN SCHEMAS
# ==================================================

class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


# ==================================================
# SERVICE REQUEST SCHEMAS
# ==================================================

class ServiceRequestCreate(BaseModel):
    request_type: str
    subject: str
    description: str


class ServiceRequestResponse(BaseModel):
    id: int
    customer_id: int
    request_type: str
    subject: str
    description: str
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ServiceRequestStatusUpdate(BaseModel):
    status: str


# ==================================================
# ASSET & SCAN SCHEMAS
# ==================================================

class AssetCreate(BaseModel):
    customer_id: int
    name: str
    target: str


class AssetResponse(BaseModel):
    id: int
    customer_id: int
    name: str
    target: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanFindingResponse(BaseModel):
    id: int
    port: int
    service: str
    risk_level: str
    description: str | None

    model_config = ConfigDict(from_attributes=True)


class ScanResultResponse(BaseModel):
    id: int
    asset_id: int
    status: str
    open_ports_count: int
    highest_risk: str
    scanned_at: datetime
    findings: list[ScanFindingResponse] = []

    model_config = ConfigDict(from_attributes=True)


# ==================================================
# SECURITY ALERT SCHEMAS
# ==================================================

class SecurityAlertResponse(BaseModel):
    id: int
    asset_id: int
    scan_result_id: int
    message: str
    risk_level: str
    is_acknowledged: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==================================================
# ADMIN STATS SCHEMA
# ==================================================

class AdminStatsResponse(BaseModel):
    total_customers: int
    total_contacts: int
    pending_requests: int
    active_requests: int
    approved_requests: int
    total_requests: int
    unacknowledged_alerts: int


# ==================================================
# ASSET FREQUENCY SCHEMA
# ==================================================

class AssetFrequencyUpdate(BaseModel):
    scan_frequency: str


# ==================================================
# AUDIT LOG SCHEMA
# ==================================================

class AuditLogResponse(BaseModel):
    id: int
    user_id: int
    action: str
    target_type: str | None
    target_id: int | None
    details: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================================
# ==========================================================
#   ENDPOINTS
# ==========================================================
# ==========================================================


# ==================================================
# ROOT & HEALTH
# ==================================================

@app.get("/")
def root():
    return {
        "message": "CyberShield API is running",
        "status": "online"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "CyberShield API"
    }


# ==================================================
# CONTACTS
# ==================================================

@app.post("/contact")
def receive_contact(
    message: ContactMessage,
    db: Session = Depends(get_db)
):

    new_contact = models.Contact(
        name=message.name,
        phone=message.phone,
        email=message.email,
        organization=message.organization,
        service=message.service,
        message=message.message
    )

    db.add(new_contact)
    db.commit()
    db.refresh(new_contact)

    print("========================================")
    print("NEW CYBERSHIELD CONTACT")
    print("========================================")
    print(f"ID: {new_contact.id}")
    print(f"Name: {new_contact.name}")
    print(f"Phone: {new_contact.phone}")
    print(f"Email: {new_contact.email}")
    print(f"Organization: {new_contact.organization}")
    print(f"Service: {new_contact.service}")
    print(f"Message: {new_contact.message}")
    print("========================================")

    return {
        "success": True,
        "message": "Your message has been received by CyberShield.",
        "contact_id": new_contact.id
    }


@app.get("/contacts", response_model=list[ContactResponse])
def get_contacts(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    return (
        db.query(models.Contact)
        .order_by(models.Contact.id.desc())
        .all()
    )


@app.get("/contacts/{contact_id}", response_model=ContactResponse)
def get_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    contact = (
        db.query(models.Contact)
        .filter(models.Contact.id == contact_id)
        .first()
    )

    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    return contact


@app.put("/contacts/{contact_id}/status")
def update_contact_status(
    contact_id: int,
    status_update: ContactStatusUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    contact = (
        db.query(models.Contact)
        .filter(models.Contact.id == contact_id)
        .first()
    )

    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    allowed_statuses = ["new", "in progress", "resolved"]

    if status_update.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid status", "allowed_statuses": allowed_statuses}
        )

    contact.status = status_update.status
    db.commit()
    db.refresh(contact)

    audit.log_action(db, current_user.id, "update_contact_status", "contact", contact.id, f"status={contact.status}")

    return {
        "success": True,
        "message": "Contact status updated successfully",
        "contact_id": contact.id,
        "status": contact.status
    }


# ==================================================
# CUSTOMERS
# ==================================================

@app.post("/customers", response_model=CustomerResponse)
def create_customer(
    customer: CustomerCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    existing = (
        db.query(models.Customer)
        .filter(models.Customer.email == customer.email)
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="A customer with this email already exists")

    new_customer = models.Customer(**customer.model_dump())

    db.add(new_customer)
    db.commit()
    db.refresh(new_customer)

    return new_customer


@app.get("/customers", response_model=list[CustomerResponse])
def get_customers(
    status: str | None = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    query = db.query(models.Customer)

    if status:
        query = query.filter(models.Customer.status == status)

    return query.order_by(models.Customer.id.desc()).all()


@app.get("/customers/{customer_id}", response_model=CustomerResponse)
def get_customer(
    customer_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    customer = (
        db.query(models.Customer)
        .filter(models.Customer.id == customer_id)
        .first()
    )

    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    return customer


@app.put("/customers/{customer_id}", response_model=CustomerResponse)
def update_customer(
    customer_id: int,
    updates: CustomerUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    customer = (
        db.query(models.Customer)
        .filter(models.Customer.id == customer_id)
        .first()
    )

    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    update_data = updates.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(customer, field, value)

    db.commit()
    db.refresh(customer)

    audit.log_action(db, current_user.id, "update_customer", "customer", customer.id)

    return customer


@app.delete("/customers/{customer_id}")
def delete_customer(
    customer_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    customer = (
        db.query(models.Customer)
        .filter(models.Customer.id == customer_id)
        .first()
    )

    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    db.delete(customer)
    db.commit()

    audit.log_action(db, current_user.id, "delete_customer", "customer", customer_id)

    return {"success": True, "message": "Customer deleted successfully"}


# ==================================================
# USER ACCOUNTS
# ==================================================

@app.post("/accounts", response_model=UserResponse)
def create_account(
    user: UserCreate,
    db: Session = Depends(get_db)
    # current_user: models.User = Depends(deps.require_admin)  # temporarily disabled to bootstrap live admin
):
    existing = (
        db.query(models.User)
        .filter(models.User.email == user.email)
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists")

    if user.role not in ["customer", "admin"]:
        raise HTTPException(status_code=400, detail="Role must be 'customer' or 'admin'")

    new_user = models.User(
        email=user.email,
        hashed_password=security.hash_password(user.password),
        role=user.role,
        customer_id=user.customer_id
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # audit.log_action(db, current_user.id, "create_account", "user", new_user.id, f"role={new_user.role}")  # temporarily disabled

    return new_user


@app.get("/accounts", response_model=list[UserResponse])
def get_accounts(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    return (
        db.query(models.User)
        .order_by(models.User.id.desc())
        .all()
    )


# ==================================================
# AUTHENTICATION (LOGIN)
# ==================================================

@app.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(
    request: Request,
    credentials: LoginRequest,
    db: Session = Depends(get_db)
):
    user = (
        db.query(models.User)
        .filter(models.User.email == credentials.email)
        .first()
    )

    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    # Check if account is currently locked
    if user.locked_until and datetime.utcnow() < user.locked_until:
        remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60) + 1
        raise HTTPException(
            status_code=403,
            detail=f"Account temporarily locked due to repeated failed login attempts. Try again in {remaining} minute(s)."
        )

    if not security.verify_password(credentials.password, user.hashed_password):
        user.failed_login_attempts += 1

        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
            user.failed_login_attempts = 0
            db.commit()
            raise HTTPException(
                status_code=403,
                detail="Too many failed login attempts. This account has been locked for 15 minutes."
            )

        db.commit()
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="This account has been deactivated")

    # Successful login — reset the failure counter
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    token = security.create_access_token(
        data={"sub": str(user.id), "role": user.role}
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.role
    }

# ==================================================
# AUTHENTICATION ( REGISTER)
# ==================================================
@app.post("/register", response_model=TokenResponse)
@limiter.limit("5/minute")
def register_customer(
    request: Request,
    data: CustomerRegister,
    db: Session = Depends(get_db)
):
    existing_customer = (
        db.query(models.Customer)
        .filter(models.Customer.email == data.email)
        .first()
    )
    if existing_customer:
        raise HTTPException(status_code=400, detail="An account with this email already exists")

    existing_user = (
        db.query(models.User)
        .filter(models.User.email == data.email)
        .first()
    )
    if existing_user:
        raise HTTPException(status_code=400, detail="An account with this email already exists")

    new_customer = models.Customer(
        full_name=data.full_name,
        email=data.email,
        phone=data.phone,
        organization=data.organization,
        industry=data.industry,
        address=data.address
    )

    db.add(new_customer)
    db.commit()
    db.refresh(new_customer)

    new_user = models.User(
        email=data.email,
        hashed_password=security.hash_password(data.password),
        role="customer",
        customer_id=new_customer.id
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = security.create_access_token(
        data={"sub": str(new_user.id), "role": new_user.role}
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": new_user.role
    }


@app.get("/me", response_model=CustomerResponse)
def get_my_profile(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.get_current_user)
):
    if current_user.role != "customer" or current_user.customer_id is None:
        raise HTTPException(status_code=404, detail="No customer profile associated with this account")

    customer = (
        db.query(models.Customer)
        .filter(models.Customer.id == current_user.customer_id)
        .first()
    )

    if not customer:
        raise HTTPException(status_code=404, detail="Customer record not found")

    return customer


# ==================================================
# SERVICE REQUESTS
# ==================================================

@app.post("/requests", response_model=ServiceRequestResponse)
def create_service_request(
    data: ServiceRequestCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.get_current_user)
):
    if current_user.role != "customer" or current_user.customer_id is None:
        raise HTTPException(status_code=403, detail="Only customers can submit requests")

    allowed_types = ["service", "security_assessment", "support_ticket"]
    if data.request_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid request type", "allowed_types": allowed_types}
        )

    new_request = models.ServiceRequest(
        customer_id=current_user.customer_id,
        request_type=data.request_type,
        subject=data.subject,
        description=data.description
    )

    db.add(new_request)
    db.commit()
    db.refresh(new_request)

    return new_request


@app.get("/requests/my", response_model=list[ServiceRequestResponse])
def get_my_requests(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.get_current_user)
):
    if current_user.role != "customer" or current_user.customer_id is None:
        raise HTTPException(status_code=403, detail="Only customers can view their requests")

    return (
        db.query(models.ServiceRequest)
        .filter(models.ServiceRequest.customer_id == current_user.customer_id)
        .order_by(models.ServiceRequest.id.desc())
        .all()
    )


@app.get("/requests", response_model=list[ServiceRequestResponse])
def get_all_requests(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    return (
        db.query(models.ServiceRequest)
        .order_by(models.ServiceRequest.id.desc())
        .all()
    )


@app.put("/requests/{request_id}/status")
def update_request_status(
    request_id: int,
    status_update: ServiceRequestStatusUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    req = db.query(models.ServiceRequest).filter(models.ServiceRequest.id == request_id).first()

    if not req:
        raise HTTPException(status_code=404, detail="Request not found")

    allowed_statuses = ["open", "in progress", "resolved", "closed"]
    if status_update.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid status", "allowed_statuses": allowed_statuses}
        )

    req.status = status_update.status
    db.commit()
    db.refresh(req)

    audit.log_action(db, current_user.id, "update_request_status", "service_request", req.id, f"status={req.status}")

    return {"success": True, "status": req.status}


# ==================================================
# ASSETS & SCANNING
# ==================================================

@app.post("/assets", response_model=AssetResponse)
def create_asset(
    data: AssetCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    customer = db.query(models.Customer).filter(models.Customer.id == data.customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    new_asset = models.Asset(
        customer_id=data.customer_id,
        name=data.name,
        target=data.target
    )
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)

    audit.log_action(db, current_user.id, "create_asset", "asset", new_asset.id, new_asset.target)

    return new_asset


@app.get("/assets", response_model=list[AssetResponse])
def get_assets(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    return db.query(models.Asset).order_by(models.Asset.id.desc()).all()


@app.post("/assets/{asset_id}/scan", response_model=ScanResultResponse)
def run_scan(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    try:
        findings_data = scanner.scan_target(asset.target)
    except ValueError as e:
        scan_result = models.ScanResult(
            asset_id=asset.id,
            status="failed",
            open_ports_count=0,
            highest_risk="none"
        )
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        raise HTTPException(status_code=400, detail=str(e))

    highest_risk = scanner.summarize_risk(findings_data)

    scan_result = models.ScanResult(
        asset_id=asset.id,
        status="completed",
        open_ports_count=len(findings_data),
        highest_risk=highest_risk
    )
    db.add(scan_result)
    db.commit()
    db.refresh(scan_result)

    for f in findings_data:
        finding = models.ScanFinding(
            scan_result_id=scan_result.id,
            port=f["port"],
            service=f["service"],
            risk_level=f["risk_level"],
            description=f["description"]
        )
        db.add(finding)

    db.commit()
    db.refresh(scan_result)

    # Create an alert if any high-risk finding was detected
    high_risk_findings = [f for f in findings_data if f["risk_level"] == "high"]
    if high_risk_findings:
        ports_list = ", ".join(str(f["port"]) for f in high_risk_findings)
        alert = models.SecurityAlert(
            asset_id=asset.id,
            scan_result_id=scan_result.id,
            message=f"High-risk open port(s) detected on {asset.name} ({asset.target}): {ports_list}",
            risk_level="high"
        )
        db.add(alert)
        db.commit()

    audit.log_action(db, current_user.id, "run_scan", "asset", asset.id, f"scan_id={scan_result.id}, risk={highest_risk}")

    return scan_result


@app.get("/assets/{asset_id}/scans", response_model=list[ScanResultResponse])
def get_asset_scans(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.asset_id == asset_id)
        .order_by(models.ScanResult.id.desc())
        .all()
    )


# ==================================================
# SECURITY ALERTS
# ==================================================

@app.get("/alerts", response_model=list[SecurityAlertResponse])
def get_alerts(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    return (
        db.query(models.SecurityAlert)
        .order_by(models.SecurityAlert.id.desc())
        .all()
    )


@app.put("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    alert = db.query(models.SecurityAlert).filter(models.SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_acknowledged = True
    db.commit()
    db.refresh(alert)

    audit.log_action(db, current_user.id, "acknowledge_alert", "security_alert", alert.id)

    return {"success": True, "acknowledged": True}


# ==================================================
# ADMIN DASHBOARD STATS
# ==================================================

@app.get("/admin/stats", response_model=AdminStatsResponse)
def get_admin_stats(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    total_customers = db.query(models.Customer).count()
    total_contacts = db.query(models.Contact).count()

    pending_requests = db.query(models.ServiceRequest).filter(models.ServiceRequest.status == "open").count()
    active_requests = db.query(models.ServiceRequest).filter(models.ServiceRequest.status == "in progress").count()
    approved_requests = db.query(models.ServiceRequest).filter(models.ServiceRequest.status == "resolved").count()
    total_requests = db.query(models.ServiceRequest).count()
    unacknowledged_alerts = db.query(models.SecurityAlert).filter(models.SecurityAlert.is_acknowledged == False).count()

    return {
        "total_customers": total_customers,
        "total_contacts": total_contacts,
        "pending_requests": pending_requests,
        "active_requests": active_requests,
        "approved_requests": approved_requests,
        "total_requests": total_requests,
        "unacknowledged_alerts": unacknowledged_alerts
    }


# ==================================================
# ASSET FREQUENCY
# ==================================================

@app.put("/assets/{asset_id}/frequency")
def update_asset_frequency(
    asset_id: int,
    data: AssetFrequencyUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    allowed = ["disabled", "every_5_min", "daily", "weekly"]
    if data.scan_frequency not in allowed:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid frequency", "allowed_values": allowed}
        )

    asset.scan_frequency = data.scan_frequency
    db.commit()
    db.refresh(asset)

    audit.log_action(db, current_user.id, "update_asset_frequency", "asset", asset.id, f"frequency={asset.scan_frequency}")

    return {"success": True, "scan_frequency": asset.scan_frequency}


# ==================================================
# AUDIT LOGS
# ==================================================

@app.get("/audit-logs", response_model=list[AuditLogResponse])
def get_audit_logs(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(deps.require_admin)
):
    return (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.id.desc())
        .limit(200)
        .all()
    )


# ==================================================
# LOGOUT
# ==================================================
@app.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    payload = security.decode_access_token(token)

    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    jti = payload.get("jti")
    if jti:
        revoked = models.RevokedToken(jti=jti)
        db.add(revoked)
        db.commit()

    return {"success": True, "message": "Logged out successfully"}