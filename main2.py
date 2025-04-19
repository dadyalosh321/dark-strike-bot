import requests
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    ContextTypes, ConversationHandler, filters
)

CHOOSING, LOGIN_USERPASS, LOGIN_SESSION, TARGET, MODE = range(5)
user_data_store = {}
report_count = {}
stopped_users = set()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        ["تسجيل دخول (username:pass)", "تسجيل دخول (Session)"],
        ["استخراج Session/Cookie", "البلاغات"],
        ["ℹ️ معلومات الهدف", "📋 الأوامر"],
        ["⛔ إيقاف", "🔁 رجوع للقائمة"]
    ]
    await update.message.reply_text(
        "مرحبًا بك في Dark Strike 💀، اختر ما تريد:",
        reply_markup=ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    )
    return CHOOSING

async def handle_choice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text

    if text.lower().strip() in ["/start", "start", "🔁 رجوع للقائمة"]:
        return await start(update, context)

    if user_id in stopped_users:
        await update.message.reply_text("⛔ تم إيقاف جلستك. أرسل /start للعودة.")
        return ConversationHandler.END

    if "username:pass" in text:
        await update.message.reply_text("أرسل البيانات بهذا الشكل:\nusername:password")
        return LOGIN_USERPASS
    elif "Session" in text:
        await update.message.reply_text("أرسل الكوكيز بهذا الشكل:\nsessionid=...; csrftoken=...")
        return LOGIN_SESSION
    elif "استخراج" in text:
        await update.message.reply_text("أرسل بياناتك وسنرسل لك الكوكيز.")
        return LOGIN_USERPASS
    elif "البلاغات" in text:
        await update.message.reply_text("أرسل اسم المستخدم الهدف (بدون @):")
        return TARGET
    elif "📋" in text:
        await update.message.reply_text(
            "📋 *أوامر DARK STRIKE:*\n\n"
            "🔐 تسجيل دخول: `username:password`\n"
            "🧾 Session: `sessionid=...; csrftoken=...`\n"
            "🚀 بلاغ: أدخل يوزر واختر نوع البلاغ\n"
            "ℹ️ معلومات الهدف: اضغط الزر وشوف تفاصيل الحساب\n"
            "⛔ إيقاف: ينهي جلستك مؤقتًا\n"
            "🔁 رجوع للقائمة: يعيدك لقائمة البداية",
            parse_mode="Markdown"
        )
        return CHOOSING
    elif "⛔" in text:
        stopped_users.add(user_id)
        await update.message.reply_text("✅ تم إيقاف الجلسة! أرسل /start للعودة.")
        return ConversationHandler.END
    elif "ℹ️" in text:
        await update.message.reply_text("أرسل اسم المستخدم للحصول على معلومات:")
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
    response = session.post("https://www.instagram.com/accounts/login/ajax/", data=payload)
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
        await update.message.reply_text("❌ صيغة خاطئة. استخدم:\nusername:password")
        return LOGIN_USERPASS
    username, password = creds
    sessionid, csrftoken = login_and_get_cookies(username, password)
    if sessionid == "SECURITY":
        await update.message.reply_text("⚠️ الحساب يحتاج تحقق (checkpoint).")
        return ConversationHandler.END
    elif sessionid:
        user_data_store[update.effective_user.id] = f"sessionid={sessionid}; csrftoken={csrftoken};"
        await update.message.reply_text(
            f"✅ تسجيل الدخول تم!\n\nsessionid:\n`{sessionid}`\ncsrftoken:\n`{csrftoken}`",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("❌ فشل تسجيل الدخول.")
    return ConversationHandler.END

async def handle_session(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if "sessionid=" in text and "csrftoken=" in text:
        user_data_store[update.effective_user.id] = text
        await update.message.reply_text("✅ تم حفظ الجلسة.")
    else:
        await update.message.reply_text("❌ صيغة غير صحيحة.")
    return ConversationHandler.END

async def handle_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["target"] = update.message.text
    keyboard = [["spam", "sexual", "violence", "harassment"], ["ℹ️ عرض معلومات"]]
    await update.message.reply_text("اختر نوع البلاغ أو اطلب معلومات الهدف:", reply_markup=ReplyKeyboardMarkup(keyboard, one_time_keyboard=True))
    return MODE

def get_user_info(username):
    url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "X-IG-App-ID": "936619743392459"
    }
    try:
        res = requests.get(url, headers=headers)
        data = res.json()['data']['user']
        return {
            "username": data['username'],
            "full_name": data['full_name'],
            "followers": data['edge_followed_by']['count'],
            "posts": data['edge_owner_to_timeline_media']['count'],
            "is_private": data['is_private'],
            "is_verified": data['is_verified']
        }
    except:
        return None

def get_user_id(username):
    url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "X-IG-App-ID": "936619743392459"
    }
    try:
        res = requests.get(url, headers=headers)
        return res.json()['data']['user']['id']
    except:
        return None

async def handle_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    mode = update.message.text.lower()
    username = context.user_data["target"]

    if mode == "ℹ️ عرض معلومات":
        info = get_user_info(username)
        if info:
            await update.message.reply_text(
                f"ℹ️ معلومات عن @{info['username']}:\n"
                f"👤 الاسم: {info['full_name']}\n"
                f"📸 الصور: {info['posts']}\n"
                f"👥 المتابعين: {info['followers']}\n"
                f"🔐 خاص؟ {'نعم' if info['is_private'] else 'لا'}\n"
                f"✅ موثق؟ {'نعم' if info['is_verified'] else 'لا'}"
            )
        else:
            await update.message.reply_text("❌ فشل في جلب معلومات الحساب.")
        return await start(update, context)

    user_id_api = get_user_id(username)
    if not user_id_api:
        await update.message.reply_text("❌ لم يتم العثور على الحساب.")
        return await start(update, context)

    session_cookie = user_data_store.get(user_id)
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

    res = requests.post(f"https://www.instagram.com/users/{user_id_api}/report/", headers=headers, data=data)
    report_count[user_id] = report_count.get(user_id, 0) + 1

    if res.status_code == 200:
        await update.message.reply_text(
            f"✅ بلاغ رقم {report_count[user_id]} تم بنجاح!\nTarget: @{username}\nMode: {mode.capitalize()}"
        )
    else:
        await update.message.reply_text(f"❌ فشل البلاغ: {res.status_code}\n{res.text}")
    return await start(update, context)


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
