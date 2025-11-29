#!/usr/bin/env python3
# bot_auto_run.py
import os, json, tempfile, subprocess, time
from datetime import datetime
import requests

BOT_TOKEN = os.environ.get("BOT_TOKEN")
SRC_CHAT_ID = int(os.environ.get("SRC_CHAT_ID")) if os.environ.get("SRC_CHAT_ID") else None
API = f"https://api.telegram.org/bot{BOT_TOKEN}"

STATE_FILE = "state.json"
RECORDS_FILE = "records.json"

def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default
    return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def safe_iso(dt):
    return dt.replace(microsecond=0).isoformat() + "Z"

def get_updates(offset):
    params = {"timeout": 0}
    if offset:
        params["offset"] = offset
    r = requests.get(f"{API}/getUpdates", params=params, timeout=90)
    r.raise_for_status()
    return r.json().get("result", [])

def get_file_info(file_id):
    r = requests.get(f"{API}/getFile", params={"file_id": file_id}, timeout=30)
    r.raise_for_status()
    return r.json()["result"]

def download_file_path(file_path):
    url = f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_path}"
    r = requests.get(url, stream=True, timeout=60)
    r.raise_for_status()
    tmp = tempfile.NamedTemporaryFile(delete=False)
    with open(tmp.name, "wb") as f:
        for chunk in r.iter_content(1024 * 32):
            if not chunk:
                break
            f.write(chunk)
    return tmp.name

def parse_exif_date(path):
    try:
        import exifread
        with open(path, "rb") as f:
            tags = exifread.process_file(f, stop_tag="EXIF DateTimeOriginal")
            dt = tags.get("EXIF DateTimeOriginal") or tags.get("Image DateTime")
            if dt:
                s = str(dt)
                try:
                    return datetime.strptime(s, "%Y:%m:%d %H:%M:%S")
                except Exception:
                    pass
    except Exception:
        pass
    return None

def ffprobe_creation_time(path):
    try:
        out = subprocess.check_output([
            "ffprobe", "-v", "error",
            "-select_streams", "v:0",
            "-show_entries", "format_tags=creation_time",
            "-of", "default=noprint_wrappers=1:nokey=1",
            path
        ], stderr=subprocess.DEVNULL).decode().strip()
        if out:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ","%Y-%m-%dT%H:%M:%SZ","%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(out, fmt)
                except Exception:
                    continue
    except Exception:
        pass
    return None

def process_update(u, records):
    """
    u: update object from getUpdates
    records: list of existing records (will be modified in-place)
    """
    message = u.get("message") or u.get("edited_message")
    if not message:
        return
    chat = message.get("chat") or {}
    if chat.get("id") != SRC_CHAT_ID:
        return
    mid = message.get("message_id")
    # skip if already present
    if any(r.get("src_msg_id") == mid for r in records):
        return

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
        mim = message["document"].get("mime_type","")
        if mim.startswith("image"):
            ftype = "photo"
        elif mim.startswith("video"):
            ftype = "video"
        else:
            ftype = "file"
    else:
        return

    # get file path and download
    info = get_file_info(file_id)
    file_path = info.get("file_path")
    if not file_path:
        return
    tmp = download_file_path(file_path)

    # try to read date
    dt = None
    if ftype == "photo":
        dt = parse_exif_date(tmp)
    if not dt:
        dt = ffprobe_creation_time(tmp)
    if not dt:
        try:
            dt = datetime.utcfromtimestamp(os.path.getmtime(tmp))
        except Exception:
            dt = datetime.utcnow()

    # cleanup
    try:
        os.unlink(tmp)
    except Exception:
        pass

    rec = {
        "src_msg_id": mid,
        "src_file_id": file_id,
        "type": ftype,
        "created_at": safe_iso(dt)
    }
    # newest first
    records.insert(0, rec)
    print("Added:", rec)

def main():
    if not BOT_TOKEN or not SRC_CHAT_ID:
        raise SystemExit("BOT_TOKEN or SRC_CHAT_ID not set in environment")

    # Убираем webhook, чтобы polling заработал
    try:
        r = requests.get(f"{API}/deleteWebhook", timeout=10)
        r.raise_for_status()
        print("Webhook deleted:", r.json())
    except Exception as e:
        print("Failed to delete webhook:", e)

    state = load_json(STATE_FILE, {"update_offset": None})
    records = load_json(RECORDS_FILE, [])

    updates = get_updates(state.get("update_offset"))
    max_update = state.get("update_offset")
    for u in updates:
        uid = u.get("update_id")
        if uid is None:
            continue
        # process update
        process_update(u, records)
        # set offset to last processed + 1
        if max_update is None or uid >= max_update:
            max_update = uid + 1

    # save state and records
    state["update_offset"] = max_update
    save_json(STATE_FILE, state)
    save_json(RECORDS_FILE, records)
    print("Done. records:", len(records))

if __name__ == "__main__":
    main()
