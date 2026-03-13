import jinja2
from fastapi import FastAPI, Request, HTTPException, Header, Depends
from workers import WorkerEntrypoint
from supabase import create_client, Client
from typing import Optional

# Khởi tạo Jinja2
environment = jinja2.Environment()
template = environment.from_string("Hello, {{ name }}! Your license is {{ status }}.")

app = FastAPI()

# Hàm hỗ trợ khởi tạo Supabase client từ environment
def get_supabase(req: Request) -> Client:
    env = req.scope["env"]
    url: str = "https://supabase.com"
    key: str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImppamRkeHNkendmZGR6dmltbWJ3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzMzODk2ODcsImV4cCI6MjA4ODk2NTY4N30.2gcIJR8ydesxOIr5xXLO3mfc8d8k4DuPlDrBF3R89SM"
    return create_client(url, key)

# Hàm kiểm tra License Key
async def verify_license_key(
    req: Request, 
    license_key: Optional[str] = Header(None, alias="X-License-Key")
):
    if not license_key:
        raise HTTPException(status_code=401, detail="Missing License Key")
    
    supabase = get_supabase(req)
    
    # Truy vấn bảng 'licenses'
    response = supabase.table("licenses") \
        .select("*") \
        .eq("key", license_key) \
        .eq("is_active", True) \
        .execute()

    if not response.data or len(response.data) == 0:
        raise HTTPException(status_code=403, detail="Invalid or inactive License Key")
    
    return response.data[0]

@app.get("/")
async def root():
    return {"message": "FastAPI + Supabase License System"}

# Route này yêu cầu License Key trong Header (X-License-Key)
@app.get("/hi/{name}")
async def say_hi(name: str, license_info: dict = Depends(verify_license_key)):
    # Render template với thông tin từ license
    status = "Active" if license_info.get("is_active") else "Inactive"
    message = template.render(name=name, status=status)
    return {
        "message": message,
        "user_id": license_info.get("user_id") # Giả định có cột user_id
    }

@app.get("/env")
async def env(req: Request):
    env = req.scope["env"]
    # Kiểm tra xem các biến Supabase đã được nạp chưa (không nên trả về key thật)
    has_supabase = "Yes" if hasattr(env, "SUPABASE_URL") else "No"
    return {"supabase_configured": has_supabase, "message": env.MESSAGE}

class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi
        # Đảm bảo app có thể truy cập env thông qua scope
        return await asgi.fetch(app, request.js_object, self.env)
