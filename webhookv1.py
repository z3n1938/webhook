# webhook_gui_tkinter_dark.py
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from pathlib import Path
import requests

# ============ AYARLAR ============
MAX_MATCHES = 100
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_DISCORD_MSG_LEN = 1900
# ================================


def find_matches(filepath: Path, keyword: str, max_matches: int):
    matches = []
    try:
        with filepath.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f, start=1):
                if keyword.lower() in line.lower():
                    matches.append(f"{i}: {line.strip()}")
                    if len(matches) >= max_matches:
                        break
    except UnicodeDecodeError:
        try:
            with filepath.open("r", encoding="latin-1") as f:
                for i, line in enumerate(f, start=1):
                    if keyword.lower() in line.lower():
                        matches.append(f"{i}: {line.strip()}")
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


def choose_file():
    path = filedialog.askopenfilename(
        title="Bir .txt dosyası seç",
        filetypes=(("Text Files", "*.txt"), ("All Files", "*.*"))
    )
    if path:
        file_path_var.set(path)


def scan_and_send():
    file_path = file_path_var.get().strip()
    keyword = keyword_var.get().strip()
    webhook = webhook_var.get().strip()

    log_box.delete(1.0, tk.END)

    if not file_path:
        messagebox.showwarning("Eksik bilgi", "Lütfen bir dosya seç.")
        return
    if not keyword:
        messagebox.showwarning("Eksik bilgi", "Lütfen aranacak kelimeyi yaz.")
        return
    if not webhook:
        messagebox.showwarning("Eksik bilgi", "Lütfen Discord Webhook URL’sini gir.")
        return

    path = Path(file_path)
    if not path.exists():
        messagebox.showerror("Hata", "Dosya bulunamadı.")
        return
    if path.stat().st_size > MAX_FILE_SIZE:
        messagebox.showerror("Hata", f"Dosya çok büyük (> {MAX_FILE_SIZE / 1024 / 1024:.1f} MB).")
        return

    log_box.insert(tk.END, f"Dosya: {path.name}\nKelime: {keyword}\nAranıyor...\n\n")
    root.update()

    matches, err = find_matches(path, keyword, MAX_MATCHES)
    if err:
        messagebox.showerror("Okuma Hatası", err)
        return

    if not matches:
        log_box.insert(tk.END, "Eşleşme bulunamadı.\n")
        return

    matches_to_send = matches[:50]
    if len(matches) > 50:
        matches_to_send.append("... (kısaltıldı, toplam %d eşleşme)" % len(matches))

    header = f"**EŞLEŞME**: `{keyword}` bulundu — `{path.name}`\n"
    lines_text = "\n".join(matches_to_send)
    content = f"{header}```\n{lines_text}\n```"

    success, err_msg = send_webhook(webhook, content)
    if success:
        log_box.insert(tk.END, f"{len(matches_to_send)} satır Discord’a gönderildi ✅\n")
    else:
        log_box.insert(tk.END, f"Webhook hatası: {err_msg}\n")


# --- GUI Arayüzü ---
root = tk.Tk()
root.title("Dosya Tara ve Discord'a Gönder (Tkinter)")
root.geometry("650x500")
root.resizable(False, False)

# Tema değişkenleri
is_dark_mode = tk.BooleanVar(value=False)

def apply_theme():
    """Dark/Light temayı uygula."""
    if is_dark_mode.get():
        bg = "#1e1e1e"
        fg = "#ffffff"
        entry_bg = "#2d2d2d"
        entry_fg = "#ffffff"
        button_bg = "#3a3a3a"
        button_fg = "#ffffff"
        log_bg = "#2b2b2b"
    else:
        bg = "#f0f0f0"
        fg = "#000000"
        entry_bg = "#ffffff"
        entry_fg = "#000000"
        button_bg = "#4CAF50"
        button_fg = "#ffffff"
        log_bg = "#ffffff"

    root.configure(bg=bg)
    frame.configure(bg=bg)
    file_entry_frame.configure(bg=bg)

    for widget in frame.winfo_children():
        if isinstance(widget, tk.Label):
            widget.configure(bg=bg, fg=fg)
        elif isinstance(widget, tk.Entry):
            widget.configure(bg=entry_bg, fg=entry_fg, insertbackground=fg)
        elif isinstance(widget, tk.Button):
            widget.configure(bg=button_bg, fg=button_fg, activebackground="#666")
        elif isinstance(widget, scrolledtext.ScrolledText):
            widget.configure(bg=log_bg, fg=fg, insertbackground=fg)


def toggle_theme():
    is_dark_mode.set(not is_dark_mode.get())
    apply_theme()


frame = tk.Frame(root)
frame.pack(padx=10, pady=10, fill="both", expand=True)

# Tema düğmesi
theme_btn = tk.Button(frame, text="🌙 Dark Mode", command=toggle_theme)
theme_btn.pack(anchor="ne", pady=(0, 5))

tk.Label(frame, text="Discord Webhook URL:").pack(anchor="w")
webhook_var = tk.StringVar()
tk.Entry(frame, textvariable=webhook_var, width=80).pack(fill="x")

tk.Label(frame, text="Aranacak kelime:").pack(anchor="w", pady=(10, 0))
keyword_var = tk.StringVar()
tk.Entry(frame, textvariable=keyword_var, width=40).pack(fill="x")

tk.Label(frame, text="Dosya (.txt):").pack(anchor="w", pady=(10, 0))
file_path_var = tk.StringVar()
file_entry_frame = tk.Frame(frame)
file_entry_frame.pack(fill="x")
tk.Entry(file_entry_frame, textvariable=file_path_var, width=60).pack(side="left", fill="x", expand=True)
tk.Button(file_entry_frame, text="Seç...", command=choose_file).pack(side="right")

tk.Button(frame, text="Tara ve Gönder", command=scan_and_send).pack(fill="x", pady=10)

log_box = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=15)
log_box.pack(fill="both", expand=True)

apply_theme()
root.mainloop()
