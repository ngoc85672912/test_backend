import subprocess
import sys

# Danh sách các thư viện cần cài đặt
packages =[
    "webtypy>=0.1.7",
    "fastapi",
    "markupsafe",
    "jinja2",
    "sqlalchemy",
    "pydantic",
    "libpass",
    "jwt",
    # "typing",  # Lưu ý: 'typing' đã có sẵn trong Python 3.5+ nên thường không cần cài.
]

def install(package):
    """Hàm chạy lệnh pip install cho từng package"""
    try:
        # sys.executable đảm bảo pip được chạy cùng môi trường với phiên bản Python hiện tại
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✅ Đã cài đặt thành công: {package}")
    except subprocess.CalledProcessError:
        print(f"❌ Lỗi khi cài đặt: {package}")
for pkg in packages:
        install(pkg)
print("Hoàn tất quá trình cài đặt!")
from fastapi import FastAPI, Request
from workers import WorkerEntrypoint
import uuid
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, JSON
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from sqlalchemy import text

# ==========================================
# 1. CẤU HÌNH BẢO MẬT & JWT (JSON Web Token)
# ==========================================
SECRET_KEY = "856729ngoc199819981998"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# 2. CẤU HÌNH DATABASE & MODELS
# ==========================================
SQLALCHEMY_DATABASE_URL = "sqlite:///./license_system.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    licenses = relationship("LicenseDB", back_populates="owner", cascade="all, delete-orphan")

class LicenseDB(Base):
    __tablename__ = "licenses"
    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    # THÊM CỘT FINGERPRINT (LƯU DỮ LIỆU JSON)
    fingerprint = Column(JSON, nullable=True) 
    
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    owner = relationship("UserDB", back_populates="licenses")

Base.metadata.create_all(bind=engine)
# ==========================================
# KHỞI TẠO TÀI KHOẢN ADMIN MẶC ĐỊNH
# ==========================================
def init_default_admin():
    db = SessionLocal()
    try:
        # Kiểm tra xem tài khoản admin đã tồn tại chưa
        admin_user = db.query(UserDB).filter(UserDB.username == "admin").first()
        if not admin_user:
            # Nếu chưa có thì tạo mới
            hashed_pwd = get_password_hash("856729ngoc199819981998") # Mật khẩu mặc định: admin123
            new_admin = UserDB(
                username="856729ngoc199819981998", 
                email="khanhngoc981856729@gmail.com", 
                hashed_password=hashed_pwd
            )
            db.add(new_admin)
            db.commit()
            print("==================================================")
            print("✅ Đã tạo tài khoản Admin mặc định!")
            print("👉 Username : admin")
            print("👉 Password : admin123")
            print("==================================================")
    finally:
        db.close()

# Gọi hàm ngay khi file main.py được chạy
init_default_admin()
# ==========================================
# 3. PYDANTIC SCHEMAS (Validation Dữ Liệu)
# ==========================================
class Token(BaseModel):
    access_token: str
    token_type: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    class Config:
        from_attributes = True

class LicenseCreate(BaseModel):
    user_id: int
    duration_days: int

class LicenseResponse(BaseModel):
    id: int
    license_key: str
    expires_at: datetime
    is_active: bool
    fingerprint: Optional[dict] = None  # Phản hồi chứa cả fingerprint
    user_id: int
    class Config:
        from_attributes = True

# REQUEST MỚI CHO VERIFY
class VerifyRequest(BaseModel):
    license_key: str
    fingerprint: dict  # Yêu cầu client phải gửi thông tin phần cứng (Dạng JSON/Dict)

class VerifyResponse(BaseModel):
    is_valid: bool
    message: str
    days_remaining: int
    expires_at: datetime | None

# ==========================================
# 4. DEPENDENCIES
# ==========================================
def get_db():
    db = SessionLocal()
    db.execute(text("PRAGMA foreign_keys=ON;")) if engine.name == "sqlite" else None
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Không thể xác thực danh tính",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.InvalidTokenError:
        raise credentials_exception
        
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if user is None:
        raise credentials_exception
    return user

app = FastAPI(
    title="License Management API",
    description="Hệ thống quản lý License Key tích hợp Hardware Binding (JSON Fingerprint)",
    version="1.2.0"
)

@app.post("/register", response_model=UserResponse, tags=["Public - Auth"])
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(UserDB).filter(UserDB.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username đã tồn tại")
    if db.query(UserDB).filter(UserDB.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email đã tồn tại")
        
    hashed_pwd = get_password_hash(user.password)
    new_user = UserDB(username=user.username, email=user.email, hashed_password=hashed_pwd)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login", response_model=Token, tags=["Public - Auth"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sai tên đăng nhập hoặc mật khẩu")
    
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/verify/", response_model=VerifyResponse, tags=["Public - Verify Key"])
def verify_license(request: VerifyRequest, db: Session = Depends(get_db)):
    license_db = db.query(LicenseDB).filter(LicenseDB.license_key == request.license_key).first()
    
    if not license_db:
        raise HTTPException(status_code=404, detail="License key không tồn tại.")
        
    if not license_db.is_active:
        return VerifyResponse(is_valid=False, message="License key đã bị khóa.", days_remaining=0, expires_at=license_db.expires_at)
    
    # --- LOGIC KIỂM TRA FINGERPRINT MÁY ---
    if license_db.fingerprint is None:
        # Nếu chưa có thiết bị nào gắn với key này -> Lấy thiết bị hiện tại làm máy gốc (Bind Hardware)
        license_db.fingerprint = request.fingerprint
        db.commit()
        db.refresh(license_db)
    else:
        # Nếu key đã được kích hoạt -> Kiểm tra xem fingerprint gửi lên có khớp với máy gốc không
        if license_db.fingerprint != request.fingerprint:
            return VerifyResponse(
                is_valid=False, 
                message="Mã bản quyền này đang được sử dụng ở một thiết bị khác. Vui lòng liên hệ Admin.", 
                days_remaining=0, 
                expires_at=license_db.expires_at
            )
    # ----------------------------------------
    
    now_utc = datetime.now(timezone.utc)
    expires_at = license_db.expires_at.replace(tzinfo=timezone.utc) if license_db.expires_at.tzinfo is None else license_db.expires_at
    days_remaining = (expires_at - now_utc).days

    if now_utc > expires_at:
        return VerifyResponse(is_valid=False, message="License key đã hết hạn.", days_remaining=0, expires_at=expires_at)
        
    return VerifyResponse(is_valid=True, message="License key hợp lệ.", days_remaining=days_remaining, expires_at=expires_at)


# ==========================================
# 7. PRIVATE ROUTES - USER MANAGEMENT
# ==========================================

@app.get("/users/me", response_model=UserResponse, tags=["Private - Users"])
def read_users_me(current_user: UserDB = Depends(get_current_user)):
    return current_user

@app.get("/users/", response_model=list[UserResponse], tags=["Private - Users"])
def get_all_users(db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    return db.query(UserDB).all()

@app.get("/users/{user_id}", response_model=UserResponse, tags=["Private - Users"])
def get_user_by_id(user_id: int, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    return user

@app.put("/users/{user_id}", response_model=UserResponse, tags=["Private - Users"])
def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    if user_update.email:
        existing = db.query(UserDB).filter(UserDB.email == user_update.email, UserDB.id != user_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email này đã được sử dụng")
        user.email = user_update.email
    if user_update.password:
        user.hashed_password = get_password_hash(user_update.password)
        
    db.commit()
    db.refresh(user)
    return user

@app.delete("/users/{user_id}", tags=["Private - Users"])
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    db.delete(user)
    db.commit()
    return {"status": "success", "message": "Đã xóa User và toàn bộ License."}

# ==========================================
# 8. PRIVATE ROUTES - LICENSE MANAGEMENT
# ==========================================

@app.post("/licenses/", response_model=LicenseResponse, tags=["Private - Licenses"])
def create_license(lic: LicenseCreate, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    user = db.query(UserDB).filter(UserDB.id == lic.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại.")

    new_key = f"KEY-{uuid.uuid4().hex[:12].upper()}"
    expiration_date = datetime.now(timezone.utc) + timedelta(days=lic.duration_days)

    new_license = LicenseDB(license_key=new_key, expires_at=expiration_date, user_id=lic.user_id)
    db.add(new_license)
    db.commit()
    db.refresh(new_license)
    return new_license

@app.get("/licenses/", response_model=list[LicenseResponse], tags=["Private - Licenses"])
def get_all_licenses(db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    return db.query(LicenseDB).all()

@app.post("/licenses/{license_id}/reset-fingerprint", tags=["Private - Licenses"])
def reset_fingerprint(license_id: int, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    """API giúp Admin xóa thông tin máy bị khóa, cho phép User dùng key trên máy mới."""
    license_db = db.query(LicenseDB).filter(LicenseDB.id == license_id).first()
    if not license_db:
        raise HTTPException(status_code=404, detail="License không tồn tại")
        
    license_db.fingerprint = None
    db.commit()
    db.refresh(license_db)
    return {"status": "success", "message": f"Đã gỡ khóa thiết bị cho mã {license_db.license_key}."}


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi

        return await asgi.fetch(app, request.js_object, self.env)
