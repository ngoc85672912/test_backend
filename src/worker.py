import jinja2
import httpx
from urllib.parse import quote
from fastapi import FastAPI, Request, HTTPException, Header, Depends
from workers import WorkerEntrypoint
from typing import Optional

# Khởi tạo Jinja2
environment = jinja2.Environment()
template = environment.from_string("Hello, {{ name }}! Your license is {{ status }}.")

app = FastAPI()

# Hàm hỗ trợ lấy thông tin cấu hình Supabase từ environment
def get_supabase_config(req: Request) -> dict:
    env = req.scope["env"]
    # Trong thực tế, nên lấy từ env: env.SUPABASE_URL, env.SUPABASE_KEY
    # Cập nhật URL đúng định dạng của Supabase (ví dụ: https://xyz.supabase.co)
    url: str = getattr(env, "SUPABASE_URL", "https://jijddxsdzwfddzvimmbw.supabase.co")
    key: str = getattr(env, "SUPABASE_KEY", "sb_publishable_PaYFgO7F3hyee7iMI7YZ_g_bwqN3SUg")
    return {"url": url, "key": key}

# Hàm kiểm tra License Key qua REST API
async def verify_license_key(
    req: Request, 
    license_key: Optional[str] = Header(None, alias="X-License-Key")
):
    if not license_key:
        raise HTTPException(status_code=401, detail="Missing License Key")
    
    config = get_supabase_config(req)
    
    # URL encode license_key để tránh lỗi nếu key chứa ký tự đặc biệt
    safe_key = quote(license_key)
    
    # Endpoint PostgREST của Supabase
    # Tương đương: select("*").eq("key", license_key).eq("is_active", True)
    api_url = f"{config['url']}/rest/v1/licenses?key=eq.{safe_key}&is_active=eq.true&select=*"
    
    # Header bắt buộc cho Supabase API
    headers = {
        "apikey": config["key"],
        "Authorization": f"Bearer {config['key']}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

    # Gọi API bất đồng bộ
    async with httpx.AsyncClient() as client:
        response = await client.get(api_url, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to connect to Supabase API")
    
    data = response.json()

    if not data or len(data) == 0:
        raise HTTPException(status_code=403, detail="Invalid or inactive License Key")
    
    return data[0]

@app.get("/")
async def root():
    return {"message": "FastAPI + Supabase REST API License System"}

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
    has_supabase = "Yes" if hasattr(env, "SUPABASE_URL") else "No"
    return {"supabase_configured": has_supabase, "message": getattr(env, "MESSAGE", "No Message")}

class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi
        # Đảm bảo app có thể truy cập env thông qua scope
        return await asgi.fetch(app, request.js_object, self.env)
