# bot_auto_run.py
import os, json, tempfile, subprocess, time
from datetime import datetime
import requests

BOT_TOKEN = os.environ.get("BOT_TOKEN")
SRC_CHAT_ID = int(os.environ.get("SRC_CHAT_ID"))
STATE_FILE = "state.json"
RECORDS_FILE = "records.json"

if not BOT_TOKEN or not SRC_CHAT_ID:
    raise SystemExit("Set BOT_TOKEN and SRC_CHAT_ID in secrets")

API = f"https://api.telegram.org/bot{BOT_TOKEN}"

def load_state():
    if os.path.exists(STATE_FILE):
        return json.load(open(STATE_FILE, "r", encoding="utf-8"))
    return {"update_offset": 0}

def save_state(s):
    json.dump(s, open(STATE_FILE, "w", encoding="utf-8"))

def load_records():
    if os.path.exists(RECORDS_FILE):
        return json.load(open(RECORDS_FILE, "r", encoding="utf-8"))
    return []

def save_records(r):
    json.dump(r, open(RECORDS_FILE, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

def get_updates(offset):
    params = {"timeout": 0, "offset": offset}
    r = requests.get(API + "/getUpdates", params=params, timeout=60)
    r.raise_for_status()
    return r.json().get("result", [])

def download_file(file_path):
    url = f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_path}"
    r = requests.get(url, stream=True, timeout=60)
    r.raise_for_status()
    tmp = tempfile.NamedTemporaryFile(delete=False)
    with open(tmp.name, "wb") as f:
        for chunk in r.iter_content(1024*32):
            if not chunk:
                break
            f.write(chunk)
    return tmp.name

def get_file_info(file_id):
    r = requests.get(API + "/getFile", params={"file_id": file_id}, timeout=30)
    r.raise_for_status()
    return r.json()["result"]

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
                except:
                    pass
    except Exception:
        pass
    return None

def ffprobe_creation_time(path):
    try:
        out = subprocess.check_output([
            "ffprobe","-v","error",
            "-select_streams","v:0",
            "-show_entries","format_tags=creation_time",
            "-of","default=noprint_wrappers=1:nokey=1",
            path
        ], stderr=subprocess.DEVNULL).decode().strip()
        if out:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ","%Y-%m-%dT%H:%M:%SZ","%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(out, fmt)
                except:
                    continue
    except Exception:
        pass
    return None

def safe_iso(dt):
    return dt.replace(microsecond=0).isoformat() + "Z"

def process_message(msg, records):
    chat = msg.get("message", {}).get("chat")
    if not chat:
        return
    if chat.get("id") != SRC_CHAT_ID:
        return
    message = msg.get("message")
    if not message:
        return
    mid = message.get("message_id")
    # skip duplicates
    if any(r.get("src_msg_id")==mid for r in records):
        return
    file_id = None
    ftype = None
    # photos
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
            ftype="photo"
        elif mim.startswith("video"):
            ftype="video"
        else:
            ftype="file"
    else:
        return

    # get remote file path
    info = get_file_info(file_id)
    file_path = info.get("file_path")
    if not file_path:
        return
    tmp = download_file(file_path)
    # try to extract date
    dt = None
    if ftype=="photo":
        dt = parse_exif_date(tmp)
    if not dt:
        dt = ffprobe_creation_time(tmp)
    if not dt:
        # fallback to file mtime
        dt = datetime.utcfromtimestamp(os.path.getmtime(tmp))
    try:
        os.unlink(tmp)
    except:
        pass

    record = {
        "src_msg_id": mid,
        "src_file_id": file_id,
        "type": ftype,
        "created_at": safe_iso(dt)
    }
    records.insert(0, record)
    print("Added record:", record)

def main():
    state = load_state()
    records = load_records()
    updates = get_updates(state.get("update_offset", 0))
    max_update = state.get("update_offset", 0)
    for u in updates:
        # each update has 'update_id'
        uid = u.get("update_id")
        if uid is None:
            continue
        if uid >= max_update:
            max_update = uid + 1
        process_message(u, records)
    # save updated state & records
    state["update_offset"] = max_update
    save_state(state)
    save_records(records)

if __name__ == "__main__":
    main()
