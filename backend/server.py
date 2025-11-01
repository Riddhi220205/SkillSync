
from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
from bson import ObjectId

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "skillsync_secret_key_change_in_production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Create the main app
app = FastAPI(title="SkillSync API")
api_router = APIRouter(prefix="/api")

# ============= MODELS =============

class UserRole:
    JOB_SEEKER = "job_seeker"
    EMPLOYER = "employer"
    ADMIN = "admin"

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: str  # job_seeker, employer, admin
    company_name: Optional[str] = None  # for employers

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    role: str
    company_name: Optional[str] = None
    created_at: datetime
    is_active: bool = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: User

class Profile(BaseModel):
    user_id: str
    phone: Optional[str] = None
    location: Optional[str] = None
    bio: Optional[str] = None
    skills: List[str] = []
    experience: Optional[str] = None
    education: Optional[str] = None
    resume_base64: Optional[str] = None  # base64 encoded resume
    avatar_base64: Optional[str] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class ProfileUpdate(BaseModel):
    phone: Optional[str] = None
    location: Optional[str] = None
    bio: Optional[str] = None
    skills: Optional[List[str]] = None
    experience: Optional[str] = None
    education: Optional[str] = None
    resume_base64: Optional[str] = None
    avatar_base64: Optional[str] = None

class CustomQuestion(BaseModel):
    question: str
    answer_type: str = "text"  # text, yes_no, multiple_choice

class Job(BaseModel):
    id: str
    employer_id: str
    employer_name: str
    company_name: str
    title: str
    description: str
    location: str
    salary_range: Optional[str] = None
    category: str
    employment_type: str  # full_time, part_time, contract, internship
    custom_questions: List[CustomQuestion] = []
    created_at: datetime
    status: str = "active"  # active, closed, pending_approval

class JobCreate(BaseModel):
    title: str
    description: str
    location: str
    salary_range: Optional[str] = None
    category: str
    employment_type: str
    custom_questions: List[CustomQuestion] = []

class CustomAnswer(BaseModel):
    question: str
    answer: str

class Application(BaseModel):
    id: str
    job_id: str
    job_title: str
    company_name: str
    job_seeker_id: str
    job_seeker_name: str
    job_seeker_email: str
    employer_id: str
    custom_answers: List[CustomAnswer] = []
    status: str = "pending"  # pending, accepted, rejected
    applied_at: datetime
    updated_at: datetime

class ApplicationCreate(BaseModel):
    job_id: str
    custom_answers: List[CustomAnswer] = []

class ApplicationStatusUpdate(BaseModel):
    status: str  # accepted, rejected

class Message(BaseModel):
    id: str
    sender_id: str
    sender_name: str
    receiver_id: str
    receiver_name: str
    message: str
    application_id: Optional[str] = None
    created_at: datetime
    is_read: bool = False

class MessageCreate(BaseModel):
    receiver_id: str
    message: str
    application_id: Optional[str] = None

# ============= HELPER FUNCTIONS =============

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "full_name": user["full_name"],
        "role": user["role"],
        "company_name": user.get("company_name"),
        "is_active": user.get("is_active", True)
    }

# ============= AUTH ENDPOINTS =============

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserRegister):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    hashed_password = get_password_hash(user_data.password)
    user_dict = {
        "email": user_data.email,
        "password": hashed_password,
        "full_name": user_data.full_name,
        "role": user_data.role,
        "company_name": user_data.company_name,
        "created_at": datetime.utcnow(),
        "is_active": True
    }
    
    result = await db.users.insert_one(user_dict)
    user_id = str(result.inserted_id)
    
    # Create empty profile
    profile_dict = {
        "user_id": user_id,
        "phone": None,
        "location": None,
        "bio": None,
        "skills": [],
        "experience": None,
        "education": None,
        "resume_base64": None,
        "avatar_base64": None,
        "updated_at": datetime.utcnow()
    }
    await db.profiles.insert_one(profile_dict)
    
    # Create token
    access_token = create_access_token({"sub": user_id})
    
    user = User(
        id=user_id,
        email=user_data.email,
        full_name=user_data.full_name,
        role=user_data.role,
        company_name=user_data.company_name,
        created_at=user_dict["created_at"],
        is_active=True
    )
    
    return TokenResponse(access_token=access_token, user=user)

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is suspended")
    
    user_id = str(user["_id"])
    access_token = create_access_token({"sub": user_id})
    
    user_obj = User(
        id=user_id,
        email=user["email"],
        full_name=user["full_name"],
        role=user["role"],
        company_name=user.get("company_name"),
        created_at=user["created_at"],
        is_active=user.get("is_active", True)
    )
    
    return TokenResponse(access_token=access_token, user=user_obj)

@api_router.get("/auth/me", response_model=User)
async def get_me(current_user: dict = Depends(get_current_user)):
    user = await db.users.find_one({"_id": ObjectId(current_user["id"])})
    return User(
        id=str(user["_id"]),
        email=user["email"],
        full_name=user["full_name"],
        role=user["role"],
        company_name=user.get("company_name"),
        created_at=user["created_at"],
        is_active=user.get("is_active", True)
    )

# ============= PROFILE ENDPOINTS =============

@api_router.get("/profile", response_model=Profile)
async def get_profile(current_user: dict = Depends(get_current_user)):
    profile = await db.profiles.find_one({"user_id": current_user["id"]})
    if not profile:
        # Create if doesn't exist
        profile_dict = {
            "user_id": current_user["id"],
            "phone": None,
            "location": None,
            "bio": None,
            "skills": [],
            "experience": None,
            "education": None,
            "resume_base64": None,
            "avatar_base64": None,
            "updated_at": datetime.utcnow()
        }
        await db.profiles.insert_one(profile_dict)
        profile = profile_dict
    
    return Profile(**profile)

@api_router.put("/profile", response_model=Profile)
async def update_profile(profile_update: ProfileUpdate, current_user: dict = Depends(get_current_user)):
    update_dict = {k: v for k, v in profile_update.dict().items() if v is not None}
    update_dict["updated_at"] = datetime.utcnow()
    
    await db.profiles.update_one(
        {"user_id": current_user["id"]},
        {"$set": update_dict}
    )
    
    profile = await db.profiles.find_one({"user_id": current_user["id"]})
    return Profile(**profile)

@api_router.get("/profile/{user_id}", response_model=Profile)
async def get_user_profile(user_id: str, current_user: dict = Depends(get_current_user)):
    profile = await db.profiles.find_one({"user_id": user_id})
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return Profile(**profile)

# ============= JOB ENDPOINTS =============

@api_router.post("/jobs", response_model=Job)
async def create_job(job_data: JobCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != UserRole.EMPLOYER:
        raise HTTPException(status_code=403, detail="Only employers can create jobs")
    
    job_dict = job_data.dict()
    job_dict.update({
        "employer_id": current_user["id"],
        "employer_name": current_user["full_name"],
        "company_name": current_user.get("company_name", "Unknown Company"),
        "created_at": datetime.utcnow(),
        "status": "active"
    })
    
    result = await db.jobs.insert_one(job_dict)
    job_dict["id"] = str(result.inserted_id)
    
    return Job(**job_dict)

@api_router.get("/jobs", response_model=List[Job])
async def get_jobs(
    search: Optional[str] = None,
    category: Optional[str] = None,
    location: Optional[str] = None,
    employment_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    query = {"status": "active"}
    
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}},
            {"company_name": {"$regex": search, "$options": "i"}}
        ]
    
    if category:
        query["category"] = category
    
    if location:
        query["location"] = {"$regex": location, "$options": "i"}
    
    if employment_type:
        query["employment_type"] = employment_type
    
    jobs = await db.jobs.find(query).sort("created_at", -1).to_list(100)
    
    return [Job(id=str(job["_id"]), **{k: v for k, v in job.items() if k != "_id"}) for job in jobs]

@api_router.get("/jobs/my-jobs", response_model=List[Job])
async def get_my_jobs(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != UserRole.EMPLOYER:
        raise HTTPException(status_code=403, detail="Only employers can view their jobs")
    
    jobs = await db.jobs.find({"employer_id": current_user["id"]}).sort("created_at", -1).to_list(100)
    
    return [Job(id=str(job["_id"]), **{k: v for k, v in job.items() if k != "_id"}) for job in jobs]

@api_router.get("/jobs/{job_id}", response_model=Job)
async def get_job(job_id: str, current_user: dict = Depends(get_current_user)):
    job = await db.jobs.find_one({"_id": ObjectId(job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return Job(id=str(job["_id"]), **{k: v for k, v in job.items() if k != "_id"})

@api_router.delete("/jobs/{job_id}")
async def delete_job(job_id: str, current_user: dict = Depends(get_current_user)):
    job = await db.jobs.find_one({"_id": ObjectId(job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job["employer_id"] != current_user["id"] and current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    await db.jobs.delete_one({"_id": ObjectId(job_id)})
    return {"message": "Job deleted successfully"}

# ============= APPLICATION ENDPOINTS =============

@api_router.post("/applications", response_model=Application)
async def create_application(app_data: ApplicationCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != UserRole.JOB_SEEKER:
        raise HTTPException(status_code=403, detail="Only job seekers can apply")
    
    # Check if already applied
    existing = await db.applications.find_one({
        "job_id": app_data.job_id,
        "job_seeker_id": current_user["id"]
    })
    if existing:
        raise HTTPException(status_code=400, detail="Already applied to this job")
    
    # Get job details
    job = await db.jobs.find_one({"_id": ObjectId(app_data.job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    application_dict = {
        "job_id": app_data.job_id,
        "job_title": job["title"],
        "company_name": job["company_name"],
        "job_seeker_id": current_user["id"],
        "job_seeker_name": current_user["full_name"],
        "job_seeker_email": current_user["email"],
        "employer_id": job["employer_id"],
        "custom_answers": [ans.dict() for ans in app_data.custom_answers],
        "status": "pending",
        "applied_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    result = await db.applications.insert_one(application_dict)
    application_dict["id"] = str(result.inserted_id)
    
    return Application(**application_dict)

@api_router.get("/applications/my-applications", response_model=List[Application])
async def get_my_applications(current_user: dict = Depends(get_current_user)):
    if current_user["role"] == UserRole.JOB_SEEKER:
        applications = await db.applications.find(
            {"job_seeker_id": current_user["id"]}
        ).sort("applied_at", -1).to_list(100)
    elif current_user["role"] == UserRole.EMPLOYER:
        applications = await db.applications.find(
            {"employer_id": current_user["id"]}
        ).sort("applied_at", -1).to_list(100)
    else:
        raise HTTPException(status_code=403, detail="Invalid role")
    
    return [Application(id=str(app["_id"]), **{k: v for k, v in app.items() if k != "_id"}) for app in applications]

@api_router.get("/applications/{application_id}", response_model=Application)
async def get_application(application_id: str, current_user: dict = Depends(get_current_user)):
    application = await db.applications.find_one({"_id": ObjectId(application_id)})
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    
    if (application["job_seeker_id"] != current_user["id"] and 
        application["employer_id"] != current_user["id"] and
        current_user["role"] != UserRole.ADMIN):
        raise HTTPException(status_code=403, detail="Not authorized")
    
    return Application(id=str(application["_id"]), **{k: v for k, v in application.items() if k != "_id"})

@api_router.put("/applications/{application_id}/status")
async def update_application_status(
    application_id: str,
    status_update: ApplicationStatusUpdate,
    current_user: dict = Depends(get_current_user)
):
    if current_user["role"] != UserRole.EMPLOYER:
        raise HTTPException(status_code=403, detail="Only employers can update application status")
    
    application = await db.applications.find_one({"_id": ObjectId(application_id)})
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    
    if application["employer_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    await db.applications.update_one(
        {"_id": ObjectId(application_id)},
        {"$set": {"status": status_update.status, "updated_at": datetime.utcnow()}}
    )
    
    return {"message": "Application status updated successfully"}

# ============= MESSAGING ENDPOINTS =============

@api_router.post("/messages", response_model=Message)
async def send_message(message_data: MessageCreate, current_user: dict = Depends(get_current_user)):
    # Get receiver details
    receiver = await db.users.find_one({"_id": ObjectId(message_data.receiver_id)})
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")
    
    message_dict = {
        "sender_id": current_user["id"],
        "sender_name": current_user["full_name"],
        "receiver_id": message_data.receiver_id,
        "receiver_name": receiver["full_name"],
        "message": message_data.message,
        "application_id": message_data.application_id,
        "created_at": datetime.utcnow(),
        "is_read": False
    }
    
    result = await db.messages.insert_one(message_dict)
    message_dict["id"] = str(result.inserted_id)
    
    return Message(**message_dict)

@api_router.get("/messages/conversations")
async def get_conversations(current_user: dict = Depends(get_current_user)):
    # Get all messages where user is sender or receiver
    messages = await db.messages.find({
        "$or": [
            {"sender_id": current_user["id"]},
            {"receiver_id": current_user["id"]}
        ]
    }).sort("created_at", -1).to_list(1000)
    
    # Group by conversation partner
    conversations = {}
    for msg in messages:
        partner_id = msg["receiver_id"] if msg["sender_id"] == current_user["id"] else msg["sender_id"]
        partner_name = msg["receiver_name"] if msg["sender_id"] == current_user["id"] else msg["sender_name"]
        
        if partner_id not in conversations:
            conversations[partner_id] = {
                "user_id": partner_id,
                "user_name": partner_name,
                "last_message": msg["message"],
                "last_message_time": msg["created_at"],
                "unread_count": 0
            }
        
        if msg["receiver_id"] == current_user["id"] and not msg["is_read"]:
            conversations[partner_id]["unread_count"] += 1
    
    return list(conversations.values())

@api_router.get("/messages/{user_id}", response_model=List[Message])
async def get_messages_with_user(user_id: str, current_user: dict = Depends(get_current_user)):
    messages = await db.messages.find({
        "$or": [
            {"sender_id": current_user["id"], "receiver_id": user_id},
            {"sender_id": user_id, "receiver_id": current_user["id"]}
        ]
    }).sort("created_at", 1).to_list(1000)
    
    # Mark as read
    await db.messages.update_many(
        {"sender_id": user_id, "receiver_id": current_user["id"], "is_read": False},
        {"$set": {"is_read": True}}
    )
    
    return [Message(id=str(msg["_id"]), **{k: v for k, v in msg.items() if k != "_id"}) for msg in messages]

# ============= ADMIN ENDPOINTS =============

@api_router.get("/admin/users", response_model=List[User])
async def get_all_users(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users = await db.users.find().to_list(1000)
    return [User(
        id=str(user["_id"]),
        email=user["email"],
        full_name=user["full_name"],
        role=user["role"],
        company_name=user.get("company_name"),
        created_at=user["created_at"],
        is_active=user.get("is_active", True)
    ) for user in users]

@api_router.put("/admin/users/{user_id}/toggle-status")
async def toggle_user_status(user_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    new_status = not user.get("is_active", True)
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"is_active": new_status}}
    )
    
    return {"message": f"User {'activated' if new_status else 'suspended'} successfully"}

@api_router.get("/admin/jobs", response_model=List[Job])
async def get_all_jobs_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    jobs = await db.jobs.find().sort("created_at", -1).to_list(1000)
    return [Job(id=str(job["_id"]), **{k: v for k, v in job.items() if k != "_id"}) for job in jobs]

@api_router.get("/admin/stats")
async def get_admin_stats(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    total_users = await db.users.count_documents({})
    total_job_seekers = await db.users.count_documents({"role": UserRole.JOB_SEEKER})
    total_employers = await db.users.count_documents({"role": UserRole.EMPLOYER})
    total_jobs = await db.jobs.count_documents({})
    active_jobs = await db.jobs.count_documents({"status": "active"})
    total_applications = await db.applications.count_documents({})
    pending_applications = await db.applications.count_documents({"status": "pending"})
    
    return {
        "total_users": total_users,
        "total_job_seekers": total_job_seekers,
        "total_employers": total_employers,
        "total_jobs": total_jobs,
        "active_jobs": active_jobs,
        "total_applications": total_applications,
        "pending_applications": pending_applications
    }

# Include the router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()