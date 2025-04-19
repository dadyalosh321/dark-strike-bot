# ✅ الكود المدمج النهائي لبوت TELEGRAM بميزات التبليغ على إنستغرام
import requests
import json
import os
import time
import asyncio
from datetime import datetime
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    ContextTypes, ConversationHandler, filters
)

# تحميل الإعدادات من config.json
with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

SESSIONS_FILE = "sessions.json"

def load_sessions():
    if os.path.exists(SESSIONS_FILE):
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_sessions():
    with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(user_data_store, f, indent=2)

user_data_store = load_sessions()
AUTHORIZED_USERS = set()
report_counters = {}
report_errors = {}
active_reports = {}

CHOOSING, LOGIN, REPORT_USERNAME, REPORT_TYPE, INFO_STEP, AUTH = range(6)

report_reasons = {
    "spam": "1", "sexual": "8", "harassment": "2", "violence": "9",
    "hate": "4", "suicide": "5", "drugs": "7", "scam": "10", "impersonation": "6"
}

def build_report_message(done, error, username, mode):
    return f"Done: {done} / Error: {error}\nTarget: @{username}\nMode: {mode.capitalize()}"

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

def get_user_id(username):
    try:
        url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
        headers = {"User-Agent": "Mozilla/5.0", "X-IG-App-ID": "936619743392459"}
        res = requests.get(url, headers=headers)
        return res.json()["data"]["user"]["id"]
    except:
        return None

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in AUTHORIZED_USERS:
        await update.message.reply_text("🔒 أرسل كلمة المرور لاستخدام البوت:")
        return AUTH

    keyboard = [
        ["🔐 تسجيل دخول", "🧾 بلاغ", "ℹ️ معلومات الهدف"],
        ["📋 الأوامر", "🚫 تسجيل خروج"]
    ]
    await update.message.reply_text("✅ مرحباً بك في DARK STRIKE!اختر أمراً من الأسفل:",
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

async def ask_login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📝 أرسل بياناتك بهذا الشكل:username:password")
    return LOGIN

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

async def send_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    username = context.user_data.get("target_username")
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

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0",
        "Host": "i.instagram.com",
        "Cookie": f"sessionid={sessionid}; csrftoken={csrftoken}",
        "X-CSRFToken": csrftoken,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    }
    data = f"source_name=profile&reason_id={report_reasons.get(reason, '1')}&frx_context="
    res = requests.post(f"https://i.instagram.com/users/{target_id}/flag/", headers=headers, data=data)

    if res.status_code == 429:
        await update.message.reply_text("🚫 تم حظر الحساب مؤقتًا من البلاغات.")
    elif res.status_code == 200:
        report_counters[user_id] = report_counters.get(user_id, 0) + 1
        await update.message.reply_text(
            f"```{build_report_message(report_counters[user_id], 0, username, reason)}```",
            parse_mode="Markdown")
    else:
        report_errors[user_id] = report_errors.get(user_id, 0) + 1
        await update.message.reply_text(f"❌ فشل البلاغ: {res.status_code}{res.text}")
    return await start(update, context)

async def start_auto_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    username = context.user_data.get("target_username")
    reason = update.message.text.lower()

    if not username:
        await update.message.reply_text("❗ أرسل اسم المستخدم الهدف أولاً.")
        return await start(update, context)

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

    await update.message.reply_text("✅ بدء التبليغ التلقائي كل 15 ثانية. أرسل /stop لإيقافه.")
    active_reports[user_id] = True
    done, error = 0, 0

    while active_reports.get(user_id):
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0",
                "Host": "i.instagram.com",
                "Cookie": f"sessionid={sessionid}; csrftoken={csrftoken}",
                "X-CSRFToken": csrftoken,
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
            }
            data = f"source_name=profile&reason_id={report_reasons.get(reason, '1')}&frx_context="
            res = requests.post(f"https://i.instagram.com/users/{target_id}/flag/", headers=headers, data=data)

            if res.status_code == 200:
                done += 1
            else:
                error += 1

            msg = build_report_message(done, error, username, reason)
            await update.message.reply_text(f"```{msg}```", parse_mode="Markdown")
        except Exception as e:
            error += 1
            await update.message.reply_text(f"⚠️ خطأ: {str(e)}")

        await asyncio.sleep(15)

    return await start(update, context)

async def stop_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    active_reports[user_id] = False
    await update.message.reply_text("🛑 تم إيقاف التبليغ التلقائي.")
    return await start(update, context)

def main():
    token = open("bot_token.txt").read().strip()
    app = ApplicationBuilder().token(token).build()

    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler("start", start),
            MessageHandler(filters.Regex("^🔐 تسجيل دخول$"), ask_login),
            MessageHandler(filters.Regex("^🧾 بلاغ$"), start_report)
        ],
        states={
            AUTH: [MessageHandler(filters.TEXT & ~filters.COMMAND, check_password)],
            CHOOSING: [
                MessageHandler(filters.Regex("^🔐 تسجيل دخول$"), ask_login),
                MessageHandler(filters.Regex("^🧾 بلاغ$"), start_report)
            ],
            LOGIN: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_login)],
            REPORT_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_report_type)],
            REPORT_TYPE: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, send_report),
                CommandHandler("auto", start_auto_report)
            ]
        },
        fallbacks=[
            CommandHandler("start", start),
            CommandHandler("auto", start_auto_report),
            CommandHandler("stop", stop_report)
        ]
    )

    app.add_handler(conv_handler)
    app.run_polling()

if __name__ == "__main__":
    main()
