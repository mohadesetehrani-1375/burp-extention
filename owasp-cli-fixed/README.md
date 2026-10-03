# OWASP API Security Top 10 (2023) — ابزار مستقل خط‌فرمان (CLI)

ده اسکریپت پایتون مستقل. هرکدام را **جداگانه** اجرا کنید.
نیازی به Burp یا Jython نیست — فقط Python 3.8+ و `requests`.

```
pip install requests
```

## قانون اصلی: آدرس هدف همیشه لازم است

هیچ مقدار پیش‌فرضی برای IP/API وجود ندارد.

### روش ۱ — با فلگ (پیشنهادی برای اتوماسیون)

```bash
python3 api1_bola.py --target https://api.example.com \
    --paths /api/v1/users/1,/api/v1/orders/1 \
    --auth "Bearer <TOKEN>" \
    --active
```

### روش ۲ — حالت تعاملی (اگر هیچ آرگومانی ندهید)

```bash
python3 api1_bola.py
```

اسکریپت از شما می‌پرسد:
- آدرس IP یا URL هدف
- مسیرهای API
- توکن Authorization (اختیاری)
- فعال‌سازی Active؟ و ...

## اجرای تک‌تک اسکریپت‌ها

```bash
# API1 - BOLA
python3 api1_bola.py --target https://api.example.com \
    --paths /api/v1/users/1,/api/v1/orders/1 \
    --auth "Bearer <توکن A>" --alt-auth "Bearer <توکن B>" --active

# API2 - Broken Authentication
python3 api2_auth.py --target https://api.example.com \
    --paths /api/v1/profile --auth "Bearer <TOKEN>" --active

# API3 - BOPLA
python3 api3_bopla.py --target https://api.example.com \
    --paths /api/v1/users/1 --auth "Bearer <TOKEN>" --active

# API4 - Unrestricted Resource Consumption
python3 api4_resource.py --target https://api.example.com \
    --paths /api/v1/items --auth "Bearer <TOKEN>" --active

# API5 - BFLA
python3 api5_bfla.py --target https://api.example.com \
    --paths /admin,/api/v1/users/1/delete --auth "Bearer <TOKEN>" --active

# API6 - Business Flows
python3 api6_business_flow.py --target https://api.example.com \
    --paths /register,/login,/checkout

# API7 - SSRF (نیاز به --oob-host و --active)
python3 api7_ssrf.py --target https://api.example.com \
    --paths /api/v1/import --auth "Bearer <TOKEN>" \
    --body-field url --oob-host your-collaborator.example --active

# API8 - Security Misconfiguration
python3 api8_misconfig.py --target https://api.example.com \
    --paths /,/api/v1/users --auth "Bearer <TOKEN>"

# API9 - Improper Inventory Management
python3 api9_inventory.py --target https://api.example.com \
    --paths /api/v1/users,/api/v2/users,/api/v3-beta/users

# API10 - Unsafe Consumption of 3rd-Party APIs
python3 api10_third_party.py --target https://api.example.com \
    --paths /webhooks/stripe,/api/v1/checkout
```

## پارامترهای مشترک

| پارامتر | توضیح |
|---|---|
| `--target` | **اجباری.** IP یا هاست هدف (با یا بدون پورت/اسکیم). هیچ پیش‌فرضی ندارد. |
| `--paths` | لیست مسیرها با کاما. اگر ندهید، لیست نمونه داخلی استفاده می‌شود. |
| `--auth` | مقدار Authorization یا Cookie |
| `--alt-auth` | توکن هویت دوم (برای BOLA/BFLA) |
| `--active` | فعال‌سازی پروب‌های Active (پیش‌فرض خاموش) |
| `--insecure` | رد کردن چک گواهی TLS |
| `--timeout` | تایم‌اوت هر درخواست (ثانیه) |
| `--export-md PATH` | ذخیره گزارش Markdown (اختیاری) |
| `-i` / `--interactive` | اجبار به حالت تعاملی |

## ذخیره‌ی گزارش JSON روی Desktop

**همیشه و خودکار** (بدون نیاز به هیچ فلگی):

در پایان هر اجرا یک فایل با نام شبیه این روی Desktop ذخیره می‌شود:

```
owasp_api1_bola_findings_20261003_143022.json
```

اگر پوشه Desktop وجود نداشته باشد، اسکریپت خودش آن را می‌سازد.
مسیر دقیق در خروجی ترمینال چاپ می‌شود.

## محدودیت‌های صادقانه

- **API1, API3, API5**: بدون `--alt-auth` یا `--active` فقط مشاهده passive انجام می‌شود.
- **API7 (SSRF)**: بدون `--oob-host` و `--active` معنی ندارد.
- **API6, API10**: بیشتر اشاره‌گر هستند تا اثبات قطعی.

## مسئولیت

فقط روی سیستم‌هایی اجرا کنید که مجوز کتبی تست دارید.
