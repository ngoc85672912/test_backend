import httpx
from urllib.parse import quote
from datetime import datetime, timezone
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import Optional
from workers import WorkerEntrypoint

app = FastAPI()

# -------------------------------------------------------------
# 1. ĐỊNH NGHĨA SCHEMAS (Khớp với Interface của Node.js)
# -------------------------------------------------------------
class HardwareFingerprint(BaseModel):
    os_platform: str
    architecture: str
    hostname: str
    mac_address: str

class VerifyRequest(BaseModel):
    license_key: str
    fingerprint: HardwareFingerprint

# -------------------------------------------------------------
# 2. HÀM HỖ TRỢ SUPABASE
# -------------------------------------------------------------
def get_supabase_config(req: Request) -> dict:
    env = req.scope["env"]
    url: str = getattr(env, "SUPABASE_URL", "https://jijddxsdzwfddzvimmbw.supabase.co")
    key: str = getattr(env, "SUPABASE_KEY", "sb_publishable_PaYFgO7F3hyee7iMI7YZ_g_bwqN3SUg")
    return {"url": url, "key": key}

def get_supabase_headers(api_key: str) -> dict:
    return {
        "apikey": api_key,
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

# -------------------------------------------------------------
# 3. API ENDPOINT KIỂM TRA BẢN QUYỀN
# -------------------------------------------------------------
@app.post("/verify/")
async def verify_license(payload: VerifyRequest, req: Request):
    config = get_supabase_config(req)
    headers = get_supabase_headers(config["key"])
    
    safe_key = quote(payload.license_key)
    
    # Bước 1: Lấy thông tin license từ Supabase
    api_url = f"{config['url']}/rest/v1/licenses?key=eq.{safe_key}&select=*"
    
    async with httpx.AsyncClient() as client:
        res = await client.get(api_url, headers=headers)

    if res.status_code != 200:
        raise HTTPException(status_code=500, detail="Lỗi kết nối máy chủ dữ liệu.")
    
    data = res.json()
    
    if not data or len(data) == 0:
        raise HTTPException(status_code=404, detail="Mã bản quyền không tồn tại.")
        
    license_info = data[0]

    # Bước 2: Kiểm tra trạng thái khóa/kích hoạt
    if not license_info.get("is_active"):
        raise HTTPException(status_code=403, detail="Mã bản quyền đã bị vô hiệu hóa.")

    # Bước 3: Tính toán thời gian hết hạn (nếu có cột expires_at trong CSDL)
    expires_at_str = license_info.get("expires_at")
    days_remaining = 3650 # Mặc định là số lớn nếu dùng vĩnh viễn (không có expires_at)
    
    if expires_at_str:
        try:
            # Supabase trả về ISO 8601, ví dụ: "2026-12-31T23:59:59+00:00" hoặc "...Z"
            clean_date_str = expires_at_str.replace("Z", "+00:00")
            expires_dt = datetime.fromisoformat(clean_date_str)
            now_dt = datetime.now(timezone.utc)
            delta = expires_dt - now_dt
            days_remaining = delta.days
            
            if days_remaining < 0:
                raise HTTPException(status_code=403, detail="Mã bản quyền của bạn đã hết hạn.")
        except Exception as e:
            print("Date parse error:", e)

    # Bước 4: Kiểm tra Hardware Fingerprint (Khóa MAC Address)
    db_mac = license_info.get("mac_address")
    client_mac = payload.fingerprint.mac_address

    if not db_mac:
        # Cơ chế Bind (Chốt cứng máy): Nếu db_mac đang rỗng (lần đầu sử dụng), ghi MAC mới vào CSDL
        update_url = f"{config['url']}/rest/v1/licenses?key=eq.{safe_key}"
        update_payload = {
            "mac_address": client_mac,
            "hostname": payload.fingerprint.hostname, # Lưu thêm tên máy (tuỳ chọn nếu DB có cột hostname)
            "os_platform": payload.fingerprint.os_platform # Tuỳ chọn
        }
        
        async with httpx.AsyncClient() as client:
            # Dùng PATCH để update dòng hiện tại
            patch_headers = headers.copy()
            patch_headers["Prefer"] = "return=minimal" # Không cần trả về dữ liệu sau khi update
            update_res = await client.patch(update_url, headers=patch_headers, json=update_payload)
            
            if update_res.status_code not in (200, 204):
                raise HTTPException(status_code=500, detail="Lỗi hệ thống khi đăng ký thiết bị.")
    else:
        # Nếu đã có db_mac, so sánh xem có khớp với thiết bị hiện tại không
        if db_mac != client_mac:
            raise HTTPException(
                status_code=403, 
                detail="Mã bản quyền này đang được sử dụng ở một máy tính khác!"
            )

    # Bước 5: Trả kết quả thành công đúng interface VerifyResponse
    return {
        "is_valid": True,
        "message": "Xác thực bản quyền thành công!",
        "days_remaining": max(0, days_remaining),
        "expires_at": expires_at_str
    }

@app.get("/")
async def root():
    return {"message": "FastAPI + Supabase REST API License System is Running."}

# -------------------------------------------------------------
# 4. CLOUDFLARE WORKERS ENTRYPOINT
# -------------------------------------------------------------
class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi
        # Đảm bảo app có thể truy cập env thông qua scope
        return await asgi.fetch(app, request.js_object, self.env)
