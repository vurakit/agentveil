"""
Ví dụ: Kích hoạt PrivacyGuard bằng SDK (1 dòng activate).
Phù hợp cho dự án đã có sẵn nhiều chỗ gọi OpenAI.
"""

import sys
sys.path.insert(0, "../sdk/python")

import privacyguard

# ============================================================
#  BƯỚC 1: Gọi activate() 1 lần khi app khởi động
# ============================================================
privacyguard.activate(
    proxy_url="http://localhost:8080",
    role="admin",
    session_id="session-abc-123",  # tùy chọn, auto-generate nếu không set
)

# ============================================================
#  BƯỚC 2: Dùng OpenAI như bình thường - KHÔNG SỬA GÌ
# ============================================================
from openai import OpenAI

client = OpenAI()  # tự động đọc OPENAI_BASE_URL từ env (đã được activate set)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": "Mã số thuế công ty tôi là 0123456789"}
    ],
)

print(response.choices[0].message.content)

# ============================================================
#  BƯỚC 3 (tuỳ chọn): Kiểm tra skill.md
# ============================================================
report = privacyguard.audit_skill(
    proxy_url="http://localhost:8080",
    content=open("my_agent_skill.md").read(),
)

print(f"Risk Level: {report['risk_level_label']}")
print(f"Score: {report['compliance_score']}/100")
for finding in report["findings"]:
    print(f"  [{finding['severity']}] Line {finding['line']}: {finding['description']}")
