import requests
import json
import os
import time
from datetime import datetime

BOT_TOKEN = "8352798938:AAGnDHDe2aIrqxbqsY-9U_3I30L1qxoVAYA"
SRC_CHAT_ID = -1003304411940  # замените на свой chat_id
RECORDS_FILE = "records.json"
STATE_FILE = "state.json"

def safe_iso(dt):
    """Возвращает ISO формат даты"""
    if not dt:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def get_updates(offset=None):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates?timeout=10"
    if offset:
        url += f"&offset={offset}"
    r = requests.get(url)
    return r.json()

def get_file_info(file_id):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getFile?file_id={file_id}"
    r = requests.get(url)
    j = r.json()
    if j.get("ok"):
        return j["result"]
    return {}

def process_update(u, records):
    """Обрабатываем одно обновление и добавляем в records"""
    message = u.get("message") or u.get("edited_message")
    if not message:
        return

    chat = message.get("chat") or {}
    if chat.get("id") != SRC_CHAT_ID:
        return

    mid = message.get("message_id")
    if any(r.get("src_msg_id") == mid for r in records):
        return  # уже есть

    file_id = None
    ftype = None

    if message.get("photo"):
        file_id = message["photo"][-1]["file_id"]
        ftype = "photo"
    elif message.get("video"):
        file_id = message["video"]["file_id"]
        ftype = "video"
    elif message.get("document"):
        file_id = message["document"]["file_id"]
        mim = message["document"].get("mime_type", "")
        if mim.startswith("image"):
            ftype = "photo"
        elif mim.startswith("video"):
            ftype = "video"
        else:
            ftype = "file"
    else:
        return

    dt = datetime.utcfromtimestamp(message.get("date", time.time()))

    rec = {
        "src_msg_id": mid,
        "src_file_id": file_id,
        "type": ftype,
        "created_at": safe_iso(dt)
    }

    records.insert(0, rec)
    print("Добавлено:", rec)

def clean_records(records):
    """Удаляем устаревшие медиа, которых нет в Telegram"""
    new_records = []
    for r in records:
        file_id = r.get("src_file_id")
        if not file_id:
            continue
        info = get_file_info(file_id)
        if info.get("file_path"):
            new_records.append(r)
        else:
            print(f"Удаляем: {file_id}")
        time.sleep(0.1)
    return new_records

def main():
    try:
        with open(RECORDS_FILE, "r", encoding="utf-8") as f:
            records = json.load(f)
    except FileNotFoundError:
        records = []

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
    except FileNotFoundError:
        state = {"last_update_id": None}

    last_id = state.get("last_update_id")

    updates = get_updates(offset=last_id + 1 if last_id else None)
    if updates.get("ok"):
        for u in updates["result"]:
            process_update(u, records)
            state["last_update_id"] = u["update_id"]

    # чистим устаревшие
    records = clean_records(records)

    # сохраняем JSON
    with open(RECORDS_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

    print("Обновление завершено, всего медиа:", len(records))

if __name__ == "__main__":
    main()
