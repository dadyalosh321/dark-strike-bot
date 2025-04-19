import requests
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    ContextTypes, ConversationHandler, filters
)

CHOOSING, LOGIN_USERPASS, LOGIN_SESSION, TARGET, MODE = range(5)
user_data_store = {}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        ["تسجيل دخول (username:pass)", "تسجيل دخول (Session)"],
        ["استخراج Session/Cookie", "البلاغات"]
    ]
    await update.message.reply_text(
        "مرحبًا بك! اختر ما تريد:",
        reply_markup=ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    )
    return CHOOSING

async def handle_choice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if "username:pass" in text:
        await update.message.reply_text("أرسل البيانات بهذا الشكل:\nusername:password")
        return LOGIN_USERPASS
    elif "Session" in text:
        await update.message.reply_text("أرسل الكوكيز بهذا الشكل:\nsessionid=...; csrftoken=...")
        return LOGIN_SESSION
    elif "استخراج" in text:
        await update.message.reply_text("أرسل البيانات بهذا الشكل:\nusername:password")
        return LOGIN_USERPASS
    elif "البلاغات" in text:
        await update.message.reply_text("أرسل اسم المستخدم الهدف (بدون @):")
        return TARGET

def login_and_get_cookies(username, password):
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0",
        "Referer": "https://www.instagram.com/accounts/login/",
        "X-Requested-With": "XMLHttpRequest"
    })
    session.get("https://www.instagram.com/accounts/login/")
    csrf = session.cookies.get_dict().get("csrftoken", "")
    payload = {
        'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:&:{password}',
        'username': username,
        'queryParams': {},
        'optIntoOneTap': 'false'
    }
    session.headers.update({"X-CSRFToken": csrf})
    response = session.post("https://www.instagram.com/accounts/login/ajax/", data=payload, allow_redirects=True)
    if response.status_code == 200:
        json_response = response.json()
        if json_response.get("authenticated"):
            cookies = session.cookies.get_dict()
            return cookies.get("sessionid"), cookies.get("csrftoken")
        elif json_response.get("message") == "checkpoint_required":
            return "SECURITY", None
    return None, None

async def handle_userpass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    creds = update.message.text.strip().split(":")
    if len(creds) != 2:
        await update.message.reply_text("صيغة خاطئة. استخدم:\nusername:password")
        return LOGIN_USERPASS
    username, password = creds
    sessionid, csrftoken = login_and_get_cookies(username, password)
    if sessionid == "SECURITY":
        await update.message.reply_text("تطلب الحساب تحقق أمني (checkpoint).")
        return ConversationHandler.END
    elif sessionid:
        user_data_store[update.effective_user.id] = f"sessionid={sessionid}; csrftoken={csrftoken};"
        await update.message.reply_text(
            f"تم تسجيل الدخول!\n\nsessionid:\n`{sessionid}`\ncsrftoken:\n`{csrftoken}`",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("فشل تسجيل الدخول.")
    return ConversationHandler.END

async def handle_session(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if "sessionid=" in text and "csrftoken=" in text:
        user_data_store[update.effective_user.id] = text
        await update.message.reply_text("تم حفظ السيشن بنجاح.")
    else:
        await update.message.reply_text("صيغة غير صحيحة.")
    return ConversationHandler.END

async def handle_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["target"] = update.message.text
    keyboard = [["spam", "sexual", "violence", "harassment"]]
    await update.message.reply_text("اختر نوع البلاغ:", reply_markup=ReplyKeyboardMarkup(keyboard, one_time_keyboard=True))
    return MODE

def get_user_id(username):
    url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "X-IG-App-ID": "936619743392459"
    }
    try:
        res = requests.get(url, headers=headers)
        if res.status_code == 200:
            return res.json()['data']['user']['id']
        else:
            return None
    except:
        return None


async def handle_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mode = update.message.text.lower()
    username = context.user_data["target"]
    user_id = get_user_id(username)
    if not user_id:
        await update.message.reply_text("تعذر الحصول على معرف المستخدم.")
        return ConversationHandler.END

    session_cookie = user_data_store.get(update.effective_user.id)
    headers = {
        "User-Agent": "Instagram 254.0.0.19.109 Android",
        "Cookie": session_cookie,
        "X-CSRFToken": session_cookie.split("csrftoken=")[-1].split(";")[0]
    }
    reason_ids = {
        "spam": "1", "sexual": "8", "violence": "9", "harassment": "2"
    }
    data = {
        "reason_id": reason_ids.get(mode, "1"),
        "source_name": "",
        "is_spam": "true" if mode == "spam" else "false"
    }
    res = requests.post(f"https://www.instagram.com/users/{user_id}/report/", headers=headers, data=data)
    if res.status_code == 200:
        await update.message.reply_text(
            f"Done : 4 / Error : 0\nTarget : @{username}\nMode : {mode.capitalize()}"
        )
    else:
        await update.message.reply_text(f"فشل البلاغ: {res.status_code}\n{res.text}")
    return ConversationHandler.END

def main():
    token = open("bot_token.txt").read().strip()
    app = ApplicationBuilder().token(token).build()
    conv = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            CHOOSING: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_choice)],
            LOGIN_USERPASS: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_userpass)],
            LOGIN_SESSION: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_session)],
            TARGET: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_target)],
            MODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_report)],
        },
        fallbacks=[]
    )
    app.add_handler(conv)
    app.run_polling()

if __name__ == "__main__":
    main()
