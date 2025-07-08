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

# === Config ===
WATCH_PATH = os.path.expanduser("C:/Users/Win 10/Downloads")
LOG_FILE = "logs/unfazed.log"
ICON_PATH = "ico.ico"  # for toast popup icon
observer = None
is_watching = False

# === File Watch Handler ===
class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        ext = os.path.splitext(file_path)[1].lower()
        if ext in ['.exe', '.zip', '.rar', '.dll', '.bat', '.scr', '.js', '.vbs']:
            log(f"[+] New file detected: {file_path}")
            threading.Thread(target=safe_scan, args=(file_path,), daemon=True).start()

# === Logging with Toast Notification on Malware ===
def log(message):
    print(message)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")
    
    if "[MALWARE DETECTED]" in message:
        try:
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast("UNFAZED ALERT", message, duration=5, icon_path=ICON_PATH)
        except:
            print("[!] Failed to show malware alert popup.")

# === Safe scanner wrapper ===
def safe_scan(file_path):
    try:
        scan_file(file_path)
    except Exception as e:
        log(f"[!] Error scanning {file_path}: {e}")

# === Start watcher ===
def start_watching():
    global observer, is_watching
    if not is_watching:
        handler = DownloadHandler()
        observer = Observer()
        observer.schedule(handler, path=WATCH_PATH, recursive=False)
        observer.start()
        is_watching = True
        log("[✓] Watcher started.")

# === Stop watcher ===
def stop_watching():
    global observer, is_watching
    if is_watching and observer:
        observer.stop()
        observer.join()
        observer = None
        is_watching = False
        log("[X] Watcher stopped.")

# === Tray Icon (circle design) ===
def create_icon():
    img = Image.new("RGB", (64, 64), "black")
    draw = ImageDraw.Draw(img)
    draw.ellipse((8, 8, 56, 56), fill="lime")
    return img

# === Tray Menu Actions ===
def on_quit(icon, item):
    stop_watching()
    icon.stop()
    sys.exit()

def on_logs(icon, item):
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        subprocess.Popen(
            ["cmd.exe", "/k", f'type "{LOG_FILE}"'],
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    except Exception as e:
        log(f"[!] Could not open logs in CMD: {e}")

# === Run System Tray ===
def run_tray():
    signal.signal(signal.SIGINT, signal.SIG_DFL)  # Fix tray icon hang issue
    icon = Icon("UNFAZED Watcher")
    icon.icon = create_icon()
    icon.title = "UNFAZED Background Scanner"
    icon.menu = Menu(
        MenuItem("Start Watcher", lambda: start_watching(), default=True),
        MenuItem("Stop Watcher", lambda: stop_watching()),
        MenuItem("View Logs", on_logs),
        MenuItem("Quit", on_quit)
    )
    threading.Thread(target=start_watching, daemon=True).start()
    icon.run()

# === Entry point ===
if __name__ == "__main__":
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w"): pass  # clear logs on each run
    run_tray()
