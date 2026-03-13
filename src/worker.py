print("Khởi tạo API Serverless v4 (Pydantic v1)!")
import hashlib
import hmac
import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List
import uuid

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from workers import WorkerEntrypoint

# ==========================================
# 1. CÁC HÀM BẢO MẬT THUẦN PYTHON
# ==========================================
SECRET_KEY = "856729ngoc199819981998"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_password_hash(password: str) -> str:
    salt = uuid.uuid4().hex
    hashed_password = hashlib.sha256(salt.encode() + password.encode()).hexdigest()
    return f"{salt}${hashed_password}"

def verify_password(plain_password: str, hashed_password_with_salt: str) -> bool:
    try:
        salt, hashed_password = hashed_password_with_salt.split('$')
        return hmac.compare_digest(
            hashed_password,
            hashlib.sha256(salt.encode() + plain_password.encode()).hexdigest()
        )
    except (ValueError, AttributeError):
        return False

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data: str) -> bytes:
    padding = b'=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data.encode('utf-8') + padding)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire_time = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": int(expire_time.timestamp())})
    header = json.dumps({"alg": ALGORITHM, "typ": "JWT"}, separators=(",", ":")).encode('utf-8')
    payload = json.dumps(to_encode, separators=(",", ":")).encode('utf-8')
    encoded_header = base64url_encode(header)
    encoded_payload = base64url_encode(payload)
    signature = hmac.new(SECRET_KEY.encode('utf-8'), f"{encoded_header}.{encoded_payload}".encode('utf-8'), hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{base64url_encode(signature)}"

def decode_and_verify_token(token: str) -> dict:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split('.')
        expected_signature = base64url_decode(encoded_signature)
        signature = hmac.new(SECRET_KEY.encode('utf-8'), f"{encoded_header}.{encoded_payload}".encode('utf-8'), hashlib.sha256).digest()
        if not hmac.compare_digest(expected_signature, signature):
            raise ValueError("Invalid signature")
        payload = json.loads(base64url_decode(encoded_payload))
        if payload['exp'] < datetime.now(timezone.utc).timestamp():
            raise ValueError("Token has expired")
        return payload
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})

# ==========================================
# 2. IN-MEMORY DATABASE
# ==========================================
fake_users_db = {"admin": {"id": 1, "username": "admin", "email": "khanhngoc981856729@gmail.com", "hashed_password": get_password_hash("admin123")}}
fake_licenses_db = {}
user_id_counter = 2
license_id_counter = 1

# ==========================================
# 3. PYDANTIC V1 SCHEMAS
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
        orm_mode = True # SỬA LỖI: Đây là cú pháp của Pydantic V1

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
    class Config:
        orm_mode = True # SỬA LỖI: Đây là cú pháp của Pydantic V1

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
app = FastAPI(title="License API (Pydantic v1)", description="Hệ thống quản lý License Key trên Cloudflare Workers", version="4.0.0")

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_and_verify_token(token)
    username: Optional[str] = payload.get("sub")
    if not username or username not in fake_users_db:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found", headers={"WWW-Authenticate": "Bearer"})
    return fake_users_db[username]
    
# ==========================================
# 5. API ROUTES
# ==========================================
@app.post("/register", response_model=UserResponse, tags=["Public - Auth"])
def register_user(user: UserCreate):
    global user_id_counter
    if user.username in fake_users_db: raise HTTPException(status_code=400, detail="Username đã tồn tại")
    if any(u["email"] == user.email for u in fake_users_db.values()): raise HTTPException(status_code=400, detail="Email đã tồn tại")
    new_user = {"id": user_id_counter, "username": user.username, "email": user.email, "hashed_password": get_password_hash(user.password)}
    fake_users_db[user.username] = new_user
    user_id_counter += 1
    return new_user

@app.post("/login", response_model=Token, tags=["Public - Auth"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sai thông tin đăng nhập")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/verify/", response_model=VerifyResponse, tags=["Public - Verify Key"])
def verify_license(request: VerifyRequest):
    license_data = next((lic for lic in fake_licenses_db.values() if lic["license_key"] == request.license_key), None)
    if not license_data: raise HTTPException(status_code=404, detail="License key không tồn tại.")
    if not license_data["is_active"]: return VerifyResponse(is_valid=False, message="License key đã bị khóa.", days_remaining=0, expires_at=license_data["expires_at"])
    if license_data["fingerprint"] is None:
        license_data["fingerprint"] = request.fingerprint
    elif license_data["fingerprint"] != request.fingerprint:
        return VerifyResponse(is_valid=False, message="Mã bản quyền đang được dùng ở thiết bị khác.", days_remaining=0, expires_at=license_data["expires_at"])
    now_utc = datetime.now(timezone.utc)
    expires_at = license_data["expires_at"]
    days_remaining = (expires_at - now_utc).days
    if now_utc > expires_at: return VerifyResponse(is_valid=False, message="License key đã hết hạn.", days_remaining=0, expires_at=expires_at)
    return VerifyResponse(is_valid=True, message="License key hợp lệ.", days_remaining=days_remaining, expires_at=expires_at)

@app.get("/users/me", response_model=UserResponse, tags=["Private - Users"])
def read_users_me(current_user: dict = Depends(get_current_user)): return current_user

@app.get("/users/", response_model=List[UserResponse], tags=["Private - Users"])
def get_all_users(current_user: dict = Depends(get_current_user)): return list(fake_users_db.values())

@app.get("/users/{user_id}", response_model=UserResponse, tags=["Private - Users"])
def get_user_by_id(user_id: int, current_user: dict = Depends(get_current_user)):
    user = next((u for u in fake_users_db.values() if u["id"] == user_id), None)
    if not user: raise HTTPException(status_code=404, detail="User không tồn tại")
    return user

@app.put("/users/{user_id}", response_model=UserResponse, tags=["Private - Users"])
def update_user(user_id: int, user_update: UserUpdate, current_user: dict = Depends(get_current_user)):
    target_username = next((username for username, u in fake_users_db.items() if u["id"] == user_id), None)
    if not target_username: raise HTTPException(status_code=404, detail="User không tồn tại")
    user = fake_users_db[target_username]
    if user_update.email:
        if any(u["email"] == user_update.email and u["id"] != user_id for u in fake_users_db.values()):
            raise HTTPException(status_code=400, detail="Email này đã được sử dụng")
        user["email"] = user_update.email
    if user_update.password: user["hashed_password"] = get_password_hash(user_update.password)
    return user

@app.delete("/users/{user_id}", tags=["Private - Users"])
def delete_user(user_id: int, current_user: dict = Depends(get_current_user)):
    target_username = next((username for username, u in fake_users_db.items() if u["id"] == user_id), None)
    if not target_username: raise HTTPException(status_code=404, detail="User không tồn tại")
    del fake_users_db[target_username]
    for k in [k for k, v in fake_licenses_db.items() if v["user_id"] == user_id]: del fake_licenses_db[k]
    return {"status": "success", "message": "Đã xóa User và toàn bộ License liên quan."}

@app.post("/licenses/", response_model=LicenseResponse, tags=["Private - Licenses"])
def create_license(lic: LicenseCreate, current_user: dict = Depends(get_current_user)):
    global license_id_counter
    if not any(u["id"] == lic.user_id for u in fake_users_db.values()): raise HTTPException(status_code=404, detail="User không tồn tại.")
    new_license = {"id": license_id_counter, "license_key": f"KEY-{uuid.uuid4().hex[:12].upper()}", "expires_at": datetime.now(timezone.utc) + timedelta(days=lic.duration_days), "is_active": True, "fingerprint": None, "user_id": lic.user_id}
    fake_licenses_db[license_id_counter] = new_license
    license_id_counter += 1
    return new_license

@app.get("/licenses/", response_model=List[LicenseResponse], tags=["Private - Licenses"])
def get_all_licenses(current_user: dict = Depends(get_current_user)): return list(fake_licenses_db.values())

@app.post("/licenses/{license_id}/reset-fingerprint", tags=["Private - Licenses"])
def reset_fingerprint(license_id: int, current_user: dict = Depends(get_current_user)):
    if license_id not in fake_licenses_db: raise HTTPException(status_code=404, detail="License không tồn tại")
    fake_licenses_db[license_id]["fingerprint"] = None
    return {"status": "success", "message": f"Đã gỡ khóa thiết bị cho mã {fake_licenses_db[license_id]['license_key']}."}
    
# ==========================================
# CLOUDFLARE ENTRYPOINT
# ==========================================
class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi
        return await asgi.fetch(app, request.js_object, self.env)
