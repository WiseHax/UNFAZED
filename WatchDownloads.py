from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pystray import Icon, Menu, MenuItem
from PIL import Image, ImageDraw
from scanner import scan_file
import os
import threading
import sys
import subprocess
import signal
import json
from config import DOWNLOAD_WATCH_PATH, LOG_FILE_PATH, TRAY_ICON_PATH

WATCHED_EXTENSIONS_PATH = "modules/watched_extensions.json"
WATCHED_EXTENSIONS = []

try:
    with open(WATCHED_EXTENSIONS_PATH, "r") as f:
        config = json.load(f)
        WATCHED_EXTENSIONS = [ext.lower() for ext in config.get("watched_extensions", [])]
except FileNotFoundError:
    print(f"[!] Watched extensions file not found at: {WATCHED_EXTENSIONS_PATH}")
except json.JSONDecodeError:
    print(f"[!] Error decoding JSON from watched extensions file: {WATCHED_EXTENSIONS_PATH}")
except Exception as e:
    print(f"[!] Failed to load watched extensions: {e}")

observer = None
is_watching = False

class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        ext = os.path.splitext(file_path)[1].lower()
        if ext in WATCHED_EXTENSIONS:
            log(f"[+] New file detected: {file_path}")
            threading.Thread(target=safe_scan, args=(file_path,), daemon=True).start()

def log(message):
    print(message)
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
        f.write(message + "\n")
    
    if "[MALWARE DETECTED]" in message:
        try:
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast("UNFAZED ALERT", message, duration=5, icon_path=TRAY_ICON_PATH)
        except:
            print("[!] Failed to show malware alert popup.")

def safe_scan(file_path):
    try:
        scan_file(file_path)
    except Exception as e:
        log(f"[!] Error scanning {file_path}: {e}")

def start_watching():
    global observer, is_watching
    if not is_watching:
        handler = DownloadHandler()
        observer = Observer()
        observer.schedule(handler, path=DOWNLOAD_WATCH_PATH, recursive=False)
        observer.start()
        is_watching = True
        log("[✓] Watcher started.")

def stop_watching():
    global observer, is_watching
    if is_watching and observer:
        observer.stop()
        observer.join()
        observer = None
        is_watching = False
        log("[X] Watcher stopped.")

def create_icon():
    img = Image.new("RGB", (64, 64), "black")
    draw = ImageDraw.Draw(img)
    draw.ellipse((8, 8, 56, 56), fill="lime")
    return img

def on_quit(icon, item):
    stop_watching()
    icon.stop()
    sys.exit()

def on_logs(icon, item):
    try:
        os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
        subprocess.Popen(
            ["cmd.exe", "/k", f'type "{LOG_FILE_PATH}"'],
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    except Exception as e:
        log(f"[!] Could not open logs in CMD: {e}")

def run_tray():
    signal.signal(signal.SIGINT, signal.SIG_DFL)  
    icon = Icon("UNFAZED Watcher")
    icon.icon = TRAY_ICON_PATH
    icon.title = "UNFAZED Background Scanner"
    icon.menu = Menu(
        MenuItem("Start Watcher", lambda: start_watching(), default=True),
        MenuItem("Stop Watcher", lambda: stop_watching()),
        MenuItem("View Logs", on_logs),
        MenuItem("Quit", on_quit)
    )
    threading.Thread(target=start_watching, daemon=True).start()
    icon.run()

if __name__ == "__main__":
    if os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, "w"): pass  
    run_tray()
