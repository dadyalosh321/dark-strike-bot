import requests
import json
import os
import time
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    ContextTypes, ConversationHandler, filters
)

# تحميل الإعدادات من config.json
with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

# تحميل الجلسات من sessions.json
SESSIONS_FILE = "sessions.json"

def load_sessions():
    if os.path.exists(SESSIONS_FILE):
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_sessions():
    with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(user_data_store, f, indent=2)

# تهيئة متغيرات عامة
user_data_store = load_sessions()
AUTHORIZED_USERS = set()
report_counters = {}
report_errors = {}
CHOOSING, LOGIN, REPORT_USERNAME, REPORT_TYPE, INFO_STEP, AUTH = range(6)

# أنواع البلاغات المدعومة
report_reasons = {
    "spam": "1",
    "sexual": "8",
    "harassment": "2",
    "violence": "9",
    "hate": "4",
    "suicide": "5",
    "drugs": "7",
    "scam": "10",
    "impersonation": "6"
}
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    # تحقق من كلمة السر
    if user_id not in AUTHORIZED_USERS:
        await update.message.reply_text("🔒 أرسل كلمة المرور لاستخدام البوت:")
        return AUTH

    keyboard = [
        ["🔐 تسجيل دخول", "🧾 بلاغ", "ℹ️ معلومات الهدف"],
        ["📋 الأوامر", "🚫 تسجيل خروج"]
    ]
    await update.message.reply_text(
        "✅ مرحباً بك في DARK STRIKE!\nاختر أمراً من الأسفل:",
        reply_markup=ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    )
    return CHOOSING

async def check_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if update.message.text.strip() == config["password"]:
        AUTHORIZED_USERS.add(user_id)
        await update.message.reply_text("✅ تم التحقق من كلمة المرور.")
        return await start(update, context)
    else:
        await update.message.reply_text("❌ كلمة المرور غير صحيحة. حاول مرة أخرى.")
        return AUTH
def login_and_get_cookies(username, password):
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0",
        "Referer": "https://www.instagram.com/accounts/login/",
        "X-Requested-With": "XMLHttpRequest"
    })
    session.get("https://www.instagram.com/accounts/login/")
    csrf = session.cookies.get_dict().get("csrftoken", "")
    session.headers.update({"X-CSRFToken": csrf})
    res = session.post("https://www.instagram.com/accounts/login/ajax/", data={
        "enc_password": f"#PWD_INSTAGRAM_BROWSER:0:&:{password}",
        "username": username,
        "optIntoOneTap": "false"
    })
    if res.status_code == 200 and res.json().get("authenticated"):
        c = session.cookies.get_dict()
        return c.get("sessionid"), c.get("csrftoken")
    return None, None

async def handle_login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    creds = update.message.text.strip().split(":")
    if len(creds) != 2:
        await update.message.reply_text("❌ استخدم الشكل: username:password")
        return LOGIN

    sessionid, csrftoken = login_and_get_cookies(*creds)
    if sessionid:
        user_data_store[update.effective_user.id] = f"sessionid={sessionid}; csrftoken={csrftoken};"
        save_sessions()
        await update.message.reply_text("✅ تم تسجيل الدخول بنجاح!")
    else:
        await update.message.reply_text("❌ فشل تسجيل الدخول.")
    return await start(update, context)
async def logout(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if uid in user_data_store:
        del user_data_store[uid]
        save_sessions()
        await update.message.reply_text("✅ تم حذف جلستك.")
    else:
        await update.message.reply_text("ℹ️ لا توجد جلسة حالياً.")
    return await start(update, context)
async def start_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🎯 أرسل اسم المستخدم الهدف (بدون @):")
    return REPORT_USERNAME

async def get_report_type(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = update.message.text.strip()
    context.user_data["target_username"] = username
    keyboard = [[reason] for reason in report_reasons.keys()]
    await update.message.reply_text("🚨 اختر نوع البلاغ:", reply_markup=ReplyKeyboardMarkup(keyboard, one_time_keyboard=True))
    return REPORT_TYPE

def get_user_id(username):
    try:
        url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
        headers = {"User-Agent": "Mozilla/5.0", "X-IG-App-ID": "936619743392459"}
        res = requests.get(url, headers=headers)
        return res.json()["data"]["user"]["id"]
    except:
        return None

async def send_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    username = context.user_data.get("target_username")
    reason = update.message.text.lower()

    if user_id not in user_data_store:
        await update.message.reply_text("❌ لم تقم بتسجيل الدخول.")
        return await start(update, context)

    session_cookie = user_data_store[user_id]
    target_id = get_user_id(username)

    if not target_id:
        await update.message.reply_text("❌ الحساب غير موجود.")
        return await start(update, context)

    # ✅ لازم يكون داخل هذا المكان فقط
    headers = {
        "User-Agent": "Instagram 254.0.0.19.109 Android (30/11; 420dpi; 1080x1920; Xiaomi; Redmi Note 10; mojito; qcom; en_US)",
        "Cookie": session_cookie,
        "X-CSRFToken": session_cookie.split("csrftoken=")[-1].split(";")[0]
    }

    data = {
        "reason_id": report_reasons.get(reason, "1"),
        "source_name": "",
        "is_spam": "true" if reason == "spam" else "false"
    }

    # طلب البلاغ
    res = requests.post(f"https://www.instagram.com/users/{target_id}/report/", headers=headers, data=data)

    # رد الفعل
    if res.status_code == 200:
        report_counters[user_id] = report_counters.get(user_id, 0) + 1
        await update.message.reply_text(
            f"```Done : {report_counters[user_id]} / Error : 0\nTarget : @{username}\nMode : {reason}```",
            parse_mode="Markdown"
        )
    else:
        report_errors[user_id] = report_errors.get(user_id, 0) + 1
        await update.message.reply_text(
            f"❌ فشل البلاغ: {res.status_code}\n\n🔍 الرد:\n{res.text}"
        )

    return await start(update, context)

active_reports = {}

async def stop_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if active_reports.get(user_id):
        active_reports[user_id] = False
        await update.message.reply_text("🛑 تم إيقاف البلاغ التلقائي.")
    else:
        await update.message.reply_text("ℹ️ لا يوجد بلاغ تلقائي قيد التشغيل.")
    return await start(update, context)
async def show_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    success = report_counters.get(uid, 0)
    error = report_errors.get(uid, 0)
    last = context.user_data.get("target_username", "—")
    session = "✅" if uid in user_data_store else "❌"

    msg = (
        f"📊 إحصائياتك:\n"
        f"- بلاغات ناجحة: {success}\n"
        f"- بلاغات فاشلة: {error}\n"
        f"- آخر هدف: @{last}\n"
        f"- الجلسة مفعّلة: {session}"
    )
    await update.message.reply_text(msg)
async def start_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🔍 أرسل اسم المستخدم للحصول على معلوماته:")
    return INFO_STEP

def fetch_instagram_info(username):
    url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "X-IG-App-ID": "936619743392459"
    }
    try:
        res = requests.get(url, headers=headers)
        user = res.json()["data"]["user"]
        return {
            "full_name": user.get("full_name", ""),
            "followers": user["edge_followed_by"]["count"],
            "following": user["edge_follow"]["count"],
            "posts": user["edge_owner_to_timeline_media"]["count"],
            "is_private": user["is_private"],
            "is_verified": user["is_verified"],
            "biography": user.get("biography", ""),
            "profile_pic_url": user.get("profile_pic_url_hd", "")
        }
    except:
        return None

async def show_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = update.message.text.strip()
    info = fetch_instagram_info(username)

    if not info:
        await update.message.reply_text("❌ لم أتمكن من الحصول على معلومات الحساب.")
        return await start(update, context)

    msg = (
        f"📄 معلومات الحساب @{username}:\n\n"
        f"👤 الاسم: {info['full_name']}\n"
        f"👥 المتابعين: {info['followers']}\n"
        f"🔁 المتابَعين: {info['following']}\n"
        f"📸 عدد الصور: {info['posts']}\n"
        f"🔐 خاص؟ {'نعم' if info['is_private'] else 'لا'}\n"
        f"✅ موثق؟ {'نعم' if info['is_verified'] else 'لا'}\n"
        f"📝 البايو:\n{info['biography'] or '—'}"
    )

    await update.message.reply_text(msg)

    if info["profile_pic_url"]:
        await update.message.reply_photo(photo=info["profile_pic_url"])

    return await start(update, context)
import asyncio

async def start_auto_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🎯 أرسل اسم المستخدم الهدف (بدون @):")
    return REPORT_USERNAME

async def set_auto_mode(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = update.message.text.strip()
    context.user_data["target_username"] = username
    keyboard = [[reason] for reason in report_reasons.keys()]
    await update.message.reply_text("🚨 اختر نوع البلاغ للتكرار التلقائي:", reply_markup=ReplyKeyboardMarkup(keyboard, one_time_keyboard=True))
    return REPORT_TYPE

async def start_repeating_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    import time
    import asyncio
    from requests import post

    user_id = update.effective_user.id
    username = context.user_data["target_username"]
    reason = update.message.text.lower()

    if user_id not in user_data_store:
        await update.message.reply_text("❌ لم تقم بتسجيل الدخول.")
        return await start(update, context)

    session = user_data_store[user_id]
    sessionid = session.split("sessionid=")[-1].split(";")[0]
    csrftoken = session.split("csrftoken=")[-1].split(";")[0]
    target_id = get_user_id(username)

    if not target_id:
        await update.message.reply_text("❌ الحساب غير موجود.")
        return await start(update, context)

    await update.message.reply_text("✅ تم بدء البلاغ التلقائي. أرسل /stop للإيقاف.")
    active_reports[user_id] = True

    done = 0
    error = 0
    interval = config.get("report_interval", 15)

    while active_reports.get(user_id):
        try:
            res = post(
                f"https://i.instagram.com/users/{target_id}/flag/",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0",
                    "Host": "i.instagram.com",
                    "Cookie": f"sessionid={sessionid}; csrftoken={csrftoken}",
                    "X-CSRFToken": csrftoken,
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                data=f"source_name=profile&reason_id={report_reasons.get(reason, '1')}&frx_context=",
                allow_redirects=False
            )

            if res.status_code == 429:
                await update.message.reply_text(f"🚫 تم حظر الحساب مؤقتًا من البلاغات [429]")
                active_reports[user_id] = False
                break
            elif res.status_code == 500:
                await update.message.reply_text(f"❌ الحساب غير موجود [500]")
                active_reports[user_id] = False
                break
            elif res.status_code == 200:
                done += 1
            else:
                error += 1

        except Exception as e:
            error += 1
            await update.message.reply_text(f"⚠️ فشل البلاغ: {str(e)}")

        await update.message.reply_text(
            f"```Done : {done} / Error : {error}\nTarget : @{username}\nMode : {reason}```",
            parse_mode="Markdown"
        )

        await asyncio.sleep(interval)

    return await start(update, context)


async def ask_login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📝 أرسل بياناتك بهذا الشكل:\nusername:password")
    return LOGIN
def main():
    token = open("bot_token.txt").read().strip()
    app = ApplicationBuilder().token(token).build()

    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler("start", start),
            MessageHandler(filters.Regex("^🔐 تسجيل دخول$"), ask_login),
            MessageHandler(filters.Regex("^🧾 بلاغ$"), start_report),
            MessageHandler(filters.Regex("^ℹ️ معلومات الهدف$"), start_info),
            MessageHandler(filters.Regex("^📋 الأوامر$"), lambda u, c: u.message.reply_text("/start, /logout, /stats, /info, /report")),
            MessageHandler(filters.Regex("^🚫 تسجيل خروج$"), logout)
        ],
        states={
            AUTH: [MessageHandler(filters.TEXT & ~filters.COMMAND, check_password)],
           CHOOSING: [
    MessageHandler(filters.Regex("^🔐 تسجيل دخول$"), ask_login),
    MessageHandler(filters.Regex("^🧾 بلاغ$"), start_report),
    MessageHandler(filters.Regex("^ℹ️ معلومات الهدف$"), start_info),
    MessageHandler(filters.Regex("^📋 الأوامر$"), lambda u, c: u.message.reply_text("/start, /logout, /stats, /info, /report")),
    MessageHandler(filters.Regex("^🚫 تسجيل خروج$"), logout)
],

            LOGIN: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_login)],
            REPORT_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_report_type)],
            REPORT_TYPE: [MessageHandler(filters.TEXT & ~filters.COMMAND, send_report)],
            INFO_STEP: [MessageHandler(filters.TEXT & ~filters.COMMAND, show_info)]
        },
        fallbacks=[
            CommandHandler("logout", logout),
            CommandHandler("stop", stop_report),
            CommandHandler("stats", show_stats),
            CommandHandler("report", start_auto_report),
            CommandHandler("info", start_info),
            CommandHandler("start", start)
        ]
    )

    auto_report_conv = ConversationHandler(
        entry_points=[CommandHandler("report", start_auto_report)],
        states={
            REPORT_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, set_auto_mode)],
            REPORT_TYPE: [MessageHandler(filters.TEXT & ~filters.COMMAND, start_repeating_report)],
        },
        fallbacks=[CommandHandler("stop", stop_report)]
    )

    app.add_handler(conv_handler)
    app.add_handler(auto_report_conv)
    app.add_handler(CommandHandler("stats", show_stats))
    app.add_handler(CommandHandler("stop", stop_report))
    app.add_handler(CommandHandler("logout", logout))

    app.run_polling()


if __name__ == "__main__":
    main()
