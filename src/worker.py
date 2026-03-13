print("Khởi tạo API License Serverless (Full Routes)!")
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from typing import Optional
import uuid
import jwt
from workers import WorkerEntrypoint

# ==========================================
# 1. CẤU HÌNH BẢO MẬT & JWT 
# ==========================================
SECRET_KEY = "856729ngoc199819981998"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# DÙNG pbkdf2_sha256 để không bị lỗi trên Cloudflare
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
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
# 2. IN-MEMORY DATABASE (RAM TẠM THỜI ĐỂ TEST)
# ==========================================
fake_users_db = {
    "admin": {
        "id": 1,
        "username": "admin",
        "email": "khanhngoc981856729@gmail.com",
        "hashed_password": get_password_hash("khanhngoc981856729@gmail.com19981998")
    }
}
fake_licenses_db = {}
user_id_counter = 2
license_id_counter = 1

# ==========================================
# 3. PYDANTIC SCHEMAS
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

class LicenseCreate(BaseModel):
    user_id: int
    duration_days: int

class LicenseResponse(BaseModel):
    id: int
    license_key: str
    expires_at: datetime
    is_active: bool
    fingerprint: Optional[dict] = None
    user_id: int

class VerifyRequest(BaseModel):
    license_key: str
    fingerprint: dict 

class VerifyResponse(BaseModel):
    is_valid: bool
    message: str
    days_remaining: int
    expires_at: Optional[datetime] = None

# ==========================================
# 4. DEPENDENCIES & APP
# ==========================================
app = FastAPI(
    title="License Management API (Serverless)",
    description="Hệ thống quản lý License Key trên Cloudflare Workers",
    version="1.2.0"
)

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Không thể xác thực danh tính",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in fake_users_db:
            raise credentials_exception
    except jwt.InvalidTokenError:
        raise credentials_exception
        
    return fake_users_db[username]

# ==========================================
# 5. PUBLIC ROUTES
# ==========================================
@app.post("/register", response_model=UserResponse, tags=["Public - Auth"])
def register_user(user: UserCreate):
    global user_id_counter
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username đã tồn tại")
    
    for u in fake_users_db.values():
        if u["email"] == user.email:
            raise HTTPException(status_code=400, detail="Email đã tồn tại")
            
    new_user = {
        "id": user_id_counter,
        "username": user.username,
        "email": user.email,
        "hashed_password": get_password_hash(user.password)
    }
    fake_users_db[user.username] = new_user
    user_id_counter += 1
    return new_user

@app.post("/login", response_model=Token, tags=["Public - Auth"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sai thông tin đăng nhập")
    
    access_token = create_access_token(data={"sub": user["username"]}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/verify/", response_model=VerifyResponse, tags=["Public - Verify Key"])
def verify_license(request: VerifyRequest):
    license_data = None
    for lic in fake_licenses_db.values():
        if lic["license_key"] == request.license_key:
            license_data = lic
            break
            
    if not license_data:
        raise HTTPException(status_code=404, detail="License key không tồn tại.")
        
    if not license_data["is_active"]:
        return VerifyResponse(is_valid=False, message="License key đã bị khóa.", days_remaining=0, expires_at=license_data["expires_at"])
    
    if license_data["fingerprint"] is None:
        license_data["fingerprint"] = request.fingerprint
    else:
        if license_data["fingerprint"] != request.fingerprint:
            return VerifyResponse(is_valid=False, message="Mã bản quyền đang được dùng ở thiết bị khác.", days_remaining=0, expires_at=license_data["expires_at"])
    
    now_utc = datetime.now(timezone.utc)
    expires_at = license_data["expires_at"]
    days_remaining = (expires_at - now_utc).days

    if now_utc > expires_at:
        return VerifyResponse(is_valid=False, message="License key đã hết hạn.", days_remaining=0, expires_at=expires_at)
        
    return VerifyResponse(is_valid=True, message="License key hợp lệ.", days_remaining=days_remaining, expires_at=expires_at)


# ==========================================
# 6. PRIVATE ROUTES - USER MANAGEMENT
# ==========================================
@app.get("/users/me", response_model=UserResponse, tags=["Private - Users"])
def read_users_me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.get("/users/", response_model=list[UserResponse], tags=["Private - Users"])
def get_all_users(current_user: dict = Depends(get_current_user)):
    return list(fake_users_db.values())

@app.get("/users/{user_id}", response_model=UserResponse, tags=["Private - Users"])
def get_user_by_id(user_id: int, current_user: dict = Depends(get_current_user)):
    for u in fake_users_db.values():
        if u["id"] == user_id:
            return u
    raise HTTPException(status_code=404, detail="User không tồn tại")

@app.put("/users/{user_id}", response_model=UserResponse, tags=["Private - Users"])
def update_user(user_id: int, user_update: UserUpdate, current_user: dict = Depends(get_current_user)):
    target_username = None
    for username, u in fake_users_db.items():
        if u["id"] == user_id:
            target_username = username
            break
            
    if not target_username:
        raise HTTPException(status_code=404, detail="User không tồn tại")
        
    user = fake_users_db[target_username]
    
    if user_update.email:
        # Check email trùng
        for u in fake_users_db.values():
            if u["email"] == user_update.email and u["id"] != user_id:
                raise HTTPException(status_code=400, detail="Email này đã được sử dụng")
        user["email"] = user_update.email
        
    if user_update.password:
        user["hashed_password"] = get_password_hash(user_update.password)
        
    return user

@app.delete("/users/{user_id}", tags=["Private - Users"])
def delete_user(user_id: int, current_user: dict = Depends(get_current_user)):
    target_username = None
    for username, u in fake_users_db.items():
        if u["id"] == user_id:
            target_username = username
            break
            
    if not target_username:
        raise HTTPException(status_code=404, detail="User không tồn tại")
        
    del fake_users_db[target_username]
    
    # Xóa cả license thuộc về user này
    keys_to_delete = [k for k, v in fake_licenses_db.items() if v["user_id"] == user_id]
    for k in keys_to_delete:
        del fake_licenses_db[k]
        
    return {"status": "success", "message": "Đã xóa User và toàn bộ License liên quan."}

# ==========================================
# 7. PRIVATE ROUTES - LICESES MANAGEMENT
# ==========================================
@app.post("/licenses/", response_model=LicenseResponse, tags=["Private - Licenses"])
def create_license(lic: LicenseCreate, current_user: dict = Depends(get_current_user)):
    global license_id_counter
    
    user_exists = any(u["id"] == lic.user_id for u in fake_users_db.values())
    if not user_exists:
        raise HTTPException(status_code=404, detail="User không tồn tại.")

    new_key = f"KEY-{uuid.uuid4().hex[:12].upper()}"
    expiration_date = datetime.now(timezone.utc) + timedelta(days=lic.duration_days)

    new_license = {
        "id": license_id_counter,
        "license_key": new_key,
        "expires_at": expiration_date,
        "is_active": True,
        "fingerprint": None,
        "user_id": lic.user_id
    }
    fake_licenses_db[license_id_counter] = new_license
    license_id_counter += 1
    return new_license

@app.get("/licenses/", response_model=list[LicenseResponse], tags=["Private - Licenses"])
def get_all_licenses(current_user: dict = Depends(get_current_user)):
    return list(fake_licenses_db.values())

@app.post("/licenses/{license_id}/reset-fingerprint", tags=["Private - Licenses"])
def reset_fingerprint(license_id: int, current_user: dict = Depends(get_current_user)):
    if license_id not in fake_licenses_db:
        raise HTTPException(status_code=404, detail="License không tồn tại")
        
    fake_licenses_db[license_id]["fingerprint"] = None
    key = fake_licenses_db[license_id]["license_key"]
    return {"status": "success", "message": f"Đã gỡ khóa thiết bị cho mã {key}."}

# ==========================================
# CLOUDFLARE ENTRYPOINT
# ==========================================
class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi
        return await asgi.fetch(app, request.js_object, self.env)
