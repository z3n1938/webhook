import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from pathlib import Path
import requests
import json
from datetime import datetime

# ============ AYARLAR ============
MAX_MATCHES_PER_FILE = 50
MAX_TOTAL_MATCHES = 300
MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_DISCORD_MSG_LEN = 1900
DEFAULT_EXTENSIONS = [".txt", ".log", ".cfg", ".ini"]
HISTORY_FILE = "search_history.json"
# ================================


# ---------- FONKSİYONLAR ----------
def find_matches(filepath: Path, keyword: str, max_matches: int):
    matches = []
    try:
        with filepath.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f, start=1):
                if keyword.lower() in line.lower():
                    matches.append(f"{filepath.name} ({i}): {line.strip()}")
                    if len(matches) >= max_matches:
                        break
    except UnicodeDecodeError:
        try:
            with filepath.open("r", encoding="latin-1") as f:
                for i, line in enumerate(f, start=1):
                    if keyword.lower() in line.lower():
                        matches.append(f"{filepath.name} ({i}): {line.strip()}")
                        if len(matches) >= max_matches:
                            break
        except Exception as e:
            return [], f"Okuma hatası: {e}"
    except Exception as e:
        return [], f"Dosya hatası: {e}"
    return matches, None


def send_webhook(webhook_url: str, content: str):
    try:
        parts = [content[i:i + MAX_DISCORD_MSG_LEN] for i in range(0, len(content), MAX_DISCORD_MSG_LEN)]
        for idx, part in enumerate(parts, 1):
            if len(parts) > 1:
                part = f"**Parça {idx}/{len(parts)}**\n{part}"
            resp = requests.post(webhook_url, json={"content": part}, timeout=15)
            if resp.status_code not in (200, 204):
                return False, f"HTTP {resp.status_code}: {resp.text}"
        return True, None
    except Exception as e:
        return False, f"Bağlantı hatası: {e}"


def choose_folder():
    path = filedialog.askdirectory(title="Bir klasör seç")
    if path:
        folder_path_var.set(path)


def get_selected_extensions():
    """Listbox'tan seçilen uzantıları al."""
    selected = [filter_listbox.get(i) for i in filter_listbox.curselection()]
    return selected if selected else DEFAULT_EXTENSIONS


def save_history(keyword, folder, match_count):
    """Arama geçmişini JSON olarak kaydet."""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "keyword": keyword,
        "folder": folder,
        "matches": match_count,
    }
    history = []
    if Path(HISTORY_FILE).exists():
        try:
            history = json.loads(Path(HISTORY_FILE).read_text(encoding="utf-8"))
        except Exception:
            history = []
    history.insert(0, entry)
    Path(HISTORY_FILE).write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")


def show_history():
    if not Path(HISTORY_FILE).exists():
        messagebox.showinfo("Geçmiş", "Henüz bir geçmiş kaydı yok.")
        return

    try:
        history = json.loads(Path(HISTORY_FILE).read_text(encoding="utf-8"))
    except Exception as e:
        messagebox.showerror("Hata", f"Geçmiş okunamadı: {e}")
        return

    hist_window = tk.Toplevel(root)
    hist_window.title("📜 Arama Geçmişi")
    hist_window.geometry("500x400")
    hist_window.configure(bg="#1e1e1e" if dark_mode else "#f0f0f0")

    text_box = scrolledtext.ScrolledText(hist_window, wrap=tk.WORD)
    text_box.pack(fill="both", expand=True)
    for entry in history:
        text_box.insert(
            tk.END,
            f"[{entry['timestamp']}] 🔍 {entry['keyword']} — 📁 {entry['folder']} — {entry['matches']} sonuç\n"
        )
    text_box.configure(state="disabled")
    if dark_mode:
        text_box.configure(bg="#2d2d2d", fg="#ffffff", insertbackground="white")


def scan_and_send():
    folder_path = folder_path_var.get().strip()
    keyword = keyword_var.get().strip()
    webhook = webhook_var.get().strip()
    extensions = get_selected_extensions()

    log_box.delete(1.0, tk.END)

    if not folder_path:
        messagebox.showwarning("Eksik bilgi", "Lütfen bir klasör seç.")
        return
    if not keyword:
        messagebox.showwarning("Eksik bilgi", "Lütfen aranacak kelimeyi yaz.")
        return
    if not webhook:
        messagebox.showwarning("Eksik bilgi", "Lütfen Discord Webhook URL’sini gir.")
        return

    folder = Path(folder_path)
    if not folder.exists():
        messagebox.showerror("Hata", "Klasör bulunamadı.")
        return

    log_box.insert(tk.END, f"Klasör: {folder}\nKelime: {keyword}\nUzantılar: {extensions}\nArama başlatıldı...\n\n")
    root.update()

    all_matches = []
    scanned_files = 0

    for file in folder.rglob("*"):
        if file.suffix.lower() in extensions and file.is_file():
            if file.stat().st_size > MAX_FILE_SIZE:
                continue
            scanned_files += 1
            matches, err = find_matches(file, keyword, MAX_MATCHES_PER_FILE)
            if matches:
                all_matches.extend(matches)
            if len(all_matches) >= MAX_TOTAL_MATCHES:
                break

    if not all_matches:
        log_box.insert(tk.END, "Eşleşme bulunamadı.\n")
        save_history(keyword, folder_path, 0)
        return

    if len(all_matches) > MAX_TOTAL_MATCHES:
        all_matches = all_matches[:MAX_TOTAL_MATCHES]
        all_matches.append(f"... (Toplam {len(all_matches)} satır, kısaltıldı)")

    header = f"**KELİME BULUNDU** 🔍 `{keyword}` — `{scanned_files}` dosya tarandı\n"
    content = header + "```\n" + "\n".join(all_matches) + "\n```"

    log_box.insert(tk.END, f"{len(all_matches)} eşleşme bulundu, Discord’a gönderiliyor...\n")
    root.update()

    success, err_msg = send_webhook(webhook, content)
    if success:
        log_box.insert(tk.END, "Discord’a başarıyla gönderildi ✅\n")
    else:
        log_box.insert(tk.END, f"Webhook hatası: {err_msg}\n")

    save_history(keyword, folder_path, len(all_matches))


# ---------- DARK MODE ----------
dark_mode = False


def apply_theme():
    bg = "#1e1e1e" if dark_mode else "#f0f0f0"
    fg = "#ffffff" if dark_mode else "#000000"
    entry_bg = "#2d2d2d" if dark_mode else "white"
    btn_bg = "#4CAF50" if not dark_mode else "#3b7f4a"

    root.configure(bg=bg)
    frame.configure(bg=bg)
    folder_frame.configure(bg=bg)
    filter_frame.configure(bg=bg)

    for widget in frame.winfo_children():
        if isinstance(widget, tk.Label):
            widget.configure(bg=bg, fg=fg)
        elif isinstance(widget, tk.Entry):
            widget.configure(bg=entry_bg, fg=fg, insertbackground=fg)
        elif isinstance(widget, tk.Button):
            widget.configure(bg=btn_bg, fg="white")

    for widget in folder_frame.winfo_children():
        if isinstance(widget, tk.Entry):
            widget.configure(bg=entry_bg, fg=fg, insertbackground=fg)
        elif isinstance(widget, tk.Button):
            widget.configure(bg=btn_bg, fg="white")

    log_box.configure(bg=entry_bg, fg=fg, insertbackground=fg)
    theme_btn.configure(
        text="☀️ Aydınlık Mod" if dark_mode else "🌙 Karanlık Mod",
        bg="#444444" if dark_mode else "#dddddd",
        fg="white" if dark_mode else "black"
    )


def toggle_theme():
    global dark_mode
    dark_mode = not dark_mode
    apply_theme()


# ---------- GUI ----------
root = tk.Tk()
root.title("Klasör Tara ve Discord'a Gönder")
root.geometry("720x600")
root.resizable(False, False)

frame = tk.Frame(root)
frame.pack(padx=10, pady=10, fill="both", expand=True)

tk.Label(frame, text="Discord Webhook URL:").pack(anchor="w")
webhook_var = tk.StringVar()
tk.Entry(frame, textvariable=webhook_var, width=80).pack(fill="x")

tk.Label(frame, text="Aranacak kelime:").pack(anchor="w", pady=(10, 0))
keyword_var = tk.StringVar()
tk.Entry(frame, textvariable=keyword_var, width=40).pack(fill="x")

tk.Label(frame, text="Klasör seç veya sürükle-bırak:").pack(anchor="w", pady=(10, 0))
folder_path_var = tk.StringVar()
folder_frame = tk.Frame(frame)
folder_frame.pack(fill="x")
folder_entry = tk.Entry(folder_frame, textvariable=folder_path_var, width=60)
folder_entry.pack(side="left", fill="x", expand=True)
tk.Button(folder_frame, text="Klasör Seç", command=choose_folder).pack(side="right")


# Drag & Drop desteği
def drop(event):
    dropped = event.data.strip("{}")  # Windows path format
    if Path(dropped).is_dir():
        folder_path_var.set(dropped)


try:
    folder_entry.drop_target_register(tk.DND_FILES)
    folder_entry.dnd_bind("<<Drop>>", drop)
except Exception:
    pass  # Eğer tkinterdnd2 yoksa hata vermesin


# Tarama filtreleri
tk.Label(frame, text="Tarama Uzantıları (CTRL ile çoklu seç):").pack(anchor="w", pady=(10, 0))
filter_frame = tk.Frame(frame)
filter_frame.pack(fill="x")
filter_listbox = tk.Listbox(filter_frame, selectmode="multiple", height=5, exportselection=False)
for ext in DEFAULT_EXTENSIONS:
    filter_listbox.insert(tk.END, ext)
filter_listbox.pack(fill="x")

# Butonlar
tk.Button(frame, text="TARA ve GÖNDER", command=scan_and_send, bg="#4CAF50", fg="white").pack(fill="x", pady=8)
theme_btn = tk.Button(frame, text="🌙 Karanlık Mod", command=toggle_theme)
theme_btn.pack(fill="x", pady=(0, 8))
tk.Button(frame, text="📜 Geçmişi Göster", command=show_history, bg="#2196F3", fg="white").pack(fill="x")

# Log kutusu
log_box = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=15)
log_box.pack(fill="both", expand=True)

apply_theme()
root.mainloop()
