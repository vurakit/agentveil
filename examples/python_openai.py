"""
Ví dụ: Tích hợp PrivacyGuard với OpenAI Python SDK.
Khách hàng chỉ cần thay đổi 1 dòng duy nhất.
"""

from openai import OpenAI

# ============================================================
#  TRƯỚC KHI CÓ PRIVACYGUARD (gọi thẳng OpenAI):
# ============================================================
#  client = OpenAI(api_key="sk-...")

# ============================================================
#  SAU KHI CÀI PRIVACYGUARD (thêm base_url, thêm headers):
# ============================================================
client = OpenAI(
    api_key="sk-...",
    base_url="http://localhost:8080/v1",     # ← trỏ vào proxy
    default_headers={
        "X-Session-ID": "customer-session-001",
        "X-User-Role": "admin",              # admin | viewer | operator
    },
)

# Code gọi LLM KHÔNG CẦN THAY ĐỔI GÌ
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": "CCCD của tôi là 012345678901, email thinh@gmail.com"}
    ],
)

# PII đã được bảo vệ xuyên suốt:
# → Proxy gửi cho OpenAI: "CCCD của tôi là [CCCD_1], email [EMAIL_1]"
# → OpenAI trả lời dùng token: "Đã nhận [CCCD_1]..."
# → Proxy khôi phục trước khi trả cho bạn: "Đã nhận 012345678901..."
print(response.choices[0].message.content)
