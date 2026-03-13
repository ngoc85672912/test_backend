import httpx
from urllib.parse import quote
from datetime import datetime, timezone
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import Optional
from workers import WorkerEntrypoint

app = FastAPI()

# -------------------------------------------------------------
# 1. ĐỊNH NGHĨA SCHEMAS (Pydantic Models)
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
# 2. HÀM HỖ TRỢ SUPABASE (ĐÃ TỐI ƯU)
# -------------------------------------------------------------

def get_supabase_config(req: Request) -> dict:
    """
    Lấy cấu hình Supabase từ biến môi trường của Cloudflare Worker.
    Ném ra lỗi 500 nếu các biến môi trường quan trọng không được thiết lập.
    """
    try:
        # req.scope["env"] là cách FastAPI truy cập vào môi trường của Cloudflare
        env = req.scope["env"]
        url = env.SUPABASE_URL
        key = env.SUPABASE_KEY
        
        if not url or not key:
             raise AttributeError("Giá trị của biến môi trường không được để trống.")

        return {"url": url, "key": key}
    except AttributeError as e:
        # Lỗi này xảy ra khi SUPABASE_URL/SUPABASE_KEY không được định nghĩa trong file .json hoặc trong "secrets"
        print(f"Lỗi cấu hình: {e}")
        raise HTTPException(
            status_code=500, 
            detail="Lỗi cấu hình phía máy chủ: Thiếu biến môi trường SUPABASE_URL hoặc SUPABASE_KEY."
        )

def get_supabase_headers(api_key: str) -> dict:
    """Tạo headers chuẩn để gọi Supabase API."""
    return {
        "apikey": api_key,
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

# -------------------------------------------------------------
# 3. API ENDPOINT CHÍNH
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
        # Có thể do API Key sai hoặc Supabase bị lỗi
        raise HTTPException(status_code=res.status_code, detail="Lỗi kết nối máy chủ dữ liệu.")
    
    data = res.json()
    
    if not data:
        raise HTTPException(status_code=404, detail="Mã bản quyền không tồn tại.")
        
    license_info = data[0]

    # Bước 2: Kiểm tra trạng thái kích hoạt
    if not license_info.get("is_active"):
        raise HTTPException(status_code=403, detail="Mã bản quyền đã bị vô hiệu hóa.")

    # Bước 3: Kiểm tra và tính toán thời gian hết hạn
    expires_at_str = license_info.get("expires_at")
    days_remaining = 36500 # Mặc định là số rất lớn (coi như vĩnh viễn)
    
    if expires_at_str:
        try:
            # Chuyển đổi chuỗi ISO 8601 từ Supabase thành đối tượng datetime
            expires_dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            now_dt = datetime.now(timezone.utc)
            
            if now_dt > expires_dt:
                raise HTTPException(status_code=403, detail="Mã bản quyền của bạn đã hết hạn.")
            
            days_remaining = (expires_dt - now_dt).days
        except (ValueError, TypeError):
            # Xử lý trường hợp định dạng ngày tháng trong CSDL bị sai
            raise HTTPException(status_code=500, detail="Lỗi dữ liệu ngày hết hạn trên máy chủ.")

    # Bước 4: Kiểm tra và gán (Bind) Hardware Fingerprint
    db_mac = license_info.get("mac_address")
    client_mac = payload.fingerprint.mac_address

    if not db_mac:
        # Nếu chưa có MAC trong CSDL -> Gán MAC của máy này vào key (kích hoạt lần đầu)
        update_url = f"{config['url']}/rest/v1/licenses?key=eq.{safe_key}"
        update_payload = {
            "mac_address": client_mac,
            "hostname": payload.fingerprint.hostname,
            "os_platform": payload.fingerprint.os_platform
        }
        
        async with httpx.AsyncClient() as client:
            update_res = await client.patch(update_url, headers=headers, json=update_payload)
            
            if update_res.status_code not in (200, 204):
                raise HTTPException(status_code=500, detail="Lỗi hệ thống khi đăng ký thiết bị.")
    elif db_mac != client_mac:
        # Nếu MAC trong CSDL đã tồn tại và không khớp -> Từ chối
        raise HTTPException(status_code=403, detail="Mã bản quyền này đang được sử dụng ở một máy tính khác!")

    # Bước 5: Trả về kết quả thành công
    return {
        "is_valid": True,
        "message": "Xác thực bản quyền thành công!",
        "days_remaining": max(0, days_remaining),
        "expires_at": expires_at_str
    }

@app.get("/")
async def root():
    return {"message": "License Verification System is Active."}

# -------------------------------------------------------------
# 4. CLOUDFLARE WORKERS ENTRYPOINT
# -------------------------------------------------------------
class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi
        return await asgi.fetch(app, request.js_object, self.env)
