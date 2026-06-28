"""
Certificate-based login window for TrustVault.
"""

import time
import tkinter as tk
from tkinter import filedialog, messagebox

from config import constants, settings
from security.audit import log_security_event
from security.key_certificate import authenticate_with_certificate


BG_TOP = "#08111f"
BG_BOTTOM = "#020617"
CARD_BG = "#0f172a"
CARD_INNER = "#111c33"
CARD_BORDER = "#1f3b55"
TEXT = "#e5f3ff"
MUTED = "#8ea4b8"
ACCENT = "#00d4ff"
ACCENT_DARK = "#0284c7"
FIELD_BG = "#0b1220"
FIELD_BORDER = "#203247"
ERROR = "#ef4444"
FONT = "Segoe UI"


def show_login(root, config):
    """Show certificate-based authentication window."""
    login_win = tk.Toplevel(root)
    login_win.title("TrustVault - Certificate Login")
    login_win.geometry("980x620")
    login_win.configure(bg=BG_BOTTOM)
    login_win.resizable(False, False)
    login_win.grab_set()
    login_win.attributes("-topmost", True)
    login_win.attributes("-alpha", 0.0)

    login_win.update_idletasks()
    width = login_win.winfo_width()
    height = login_win.winfo_height()
    x = (login_win.winfo_screenwidth() // 2) - (width // 2)
    y = (login_win.winfo_screenheight() // 2) - (height // 2)
    login_win.geometry(f"{width}x{height}+{x}+{y}")

    bg_canvas = tk.Canvas(login_win, width=980, height=620, highlightthickness=0, bd=0)
    bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
    for i in range(620):
        ratio = i / 620
        r1, g1, b1 = int(BG_TOP[1:3], 16), int(BG_TOP[3:5], 16), int(BG_TOP[5:7], 16)
        r2, g2, b2 = int(BG_BOTTOM[1:3], 16), int(BG_BOTTOM[3:5], 16), int(BG_BOTTOM[5:7], 16)
        color = f"#{int(r1 + (r2-r1)*ratio):02x}{int(g1 + (g2-g1)*ratio):02x}{int(b1 + (b2-b1)*ratio):02x}"
        bg_canvas.create_line(0, i, 980, i, fill=color)
    bg_canvas.create_oval(690, -110, 1120, 310, fill="#062f4f", outline="")
    bg_canvas.create_oval(-160, 400, 280, 820, fill="#061b35", outline="")

    shadow = tk.Frame(login_win, bg="#020617")
    shadow.place(relx=0.5, rely=0.515, anchor="center", width=814, height=468)

    card = tk.Frame(login_win, bg=CARD_BG, highlightthickness=1, highlightbackground=CARD_BORDER)
    card.place(relx=0.5, rely=0.5, anchor="center", width=810, height=462)

    header = tk.Frame(card, bg=CARD_BG)
    header.pack(fill="x", padx=34, pady=(26, 12))

    mark = tk.Label(header, text="TV", bg=ACCENT, fg="#00111a", font=(FONT, 13, "bold"), width=4, height=2)
    mark.pack(side="left")

    title_box = tk.Frame(header, bg=CARD_BG)
    title_box.pack(side="left", padx=16)
    tk.Label(title_box, text="TrustVault", bg=CARD_BG, fg=TEXT,
             font=(FONT, 28, "bold")).pack(anchor="w")
    tk.Label(title_box, text="PKI-Based File Integrity Monitoring System", bg=CARD_BG, fg=MUTED,
             font=(FONT, 10)).pack(anchor="w", pady=(1, 0))

    status = tk.Label(header, text="Secure Access", bg="#082f49", fg=ACCENT,
                      font=(FONT, 10, "bold"), padx=12, pady=6)
    status.pack(side="right")

    content = tk.Frame(card, bg=CARD_BG)
    content.pack(fill="both", expand=True, padx=34, pady=(4, 0))
    content.grid_columnconfigure(0, weight=1, uniform="auth")
    content.grid_columnconfigure(1, weight=1, uniform="auth")

    left = tk.Frame(content, bg=CARD_INNER, highlightthickness=1, highlightbackground="#1e2e45")
    left.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=4)
    right = tk.Frame(content, bg=CARD_INNER, highlightthickness=1, highlightbackground="#1e2e45")
    right.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=4)

    def section_header(parent, title, subtitle):
        tk.Label(parent, text=title, bg=CARD_INNER, fg=TEXT,
                 font=(FONT, 15, "bold")).pack(anchor="w", padx=22, pady=(22, 2))
        tk.Label(parent, text=subtitle, bg=CARD_INNER, fg=MUTED,
                 font=(FONT, 9)).pack(anchor="w", padx=22, pady=(0, 14))

    def make_field(parent, label_text, show=None, textvariable=None):
        tk.Label(parent, text=label_text, bg=CARD_INNER, fg="#b8c7d7",
                 font=(FONT, 9, "bold")).pack(anchor="w", padx=22, pady=(8, 5))
        wrapper = tk.Frame(parent, bg=FIELD_BORDER, padx=1, pady=1)
        wrapper.pack(fill="x", padx=22)
        entry = tk.Entry(wrapper, textvariable=textvariable, show=show, bg=FIELD_BG, fg=TEXT,
                         insertbackground=ACCENT, relief="flat", bd=0,
                         font=(FONT, 11), highlightthickness=0)
        entry.pack(fill="x", ipady=9, padx=1, pady=1)

        def on_focus_in(_event):
            wrapper.configure(bg=ACCENT)

        def on_focus_out(_event):
            wrapper.configure(bg=FIELD_BORDER)

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)
        return entry

    section_header(left, "Traditional Login", "Account identity used for audit and access policy")
    user_entry = make_field(left, "Username")
    pass_entry = make_field(left, "Password", show="*")
    user_entry.focus_set()

    section_header(right, "Certificate Authentication", "Validate your X.509 certificate and PKCS#12 private key")
    pkcs12_var = tk.StringVar()
    path_entry = make_field(right, "PKCS#12 Keystore File (.p12 / .pfx)", textvariable=pkcs12_var)
    key_pass_entry = make_field(right, "Keystore Password", show="*")

    def browse_keystore():
        path = filedialog.askopenfilename(
            title="Select PKCS#12 keystore",
            filetypes=[("PKCS#12 Keystore", "*.p12 *.pfx"), ("All files", "*.*")],
            parent=login_win,
        )
        if path:
            pkcs12_var.set(path)

    browse_btn = tk.Button(right, text="Browse Keystore", command=browse_keystore,
                           bg="#16253a", fg=TEXT, activebackground="#1e3a5f",
                           activeforeground=TEXT, relief="flat", bd=0, cursor="hand2",
                           font=(FONT, 10, "bold"), padx=12, pady=8)
    browse_btn.pack(anchor="e", padx=22, pady=(10, 0))

    authenticated = [False]
    login_attempts = [0]
    last_attempt_time = [0]

    def attempt_login():
        current_time = time.time()
        if current_time - last_attempt_time[0] < 1:
            messagebox.showerror("Too Fast", "Please wait before trying again", parent=login_win)
            return False
        last_attempt_time[0] = current_time
        login_attempts[0] += 1

        if login_attempts[0] > 5:
            log_security_event("AUTH_LOCKOUT", user=user_entry.get().strip(),
                               description="Too many certificate authentication attempts",
                               severity="CRITICAL")
            messagebox.showerror("Locked", "Too many login attempts.", parent=login_win)
            login_win.destroy()
            root.destroy()
            return False

        username = user_entry.get().strip()
        password = pass_entry.get()
        keystore_password = key_pass_entry.get()
        pkcs12_path = pkcs12_var.get().strip()

        if not username or not password or not keystore_password or not pkcs12_path:
            messagebox.showwarning("Missing Information", "Username, passwords, and keystore are required.",
                                   parent=login_win)
            return False

        ok, message = authenticate_with_certificate(username, password, pkcs12_path, keystore_password)
        if ok:
            authenticated[0] = True
            config["last_user"] = username
            settings.save_config(config)
            login_win.destroy()
            return True

        messagebox.showerror("Access Denied", f"{message}\n\nAttempt {login_attempts[0]}/5", parent=login_win)
        return False

    actions = tk.Frame(card, bg=CARD_BG)
    actions.pack(fill="x", padx=34, pady=(18, 24))

    def make_button(parent, text, command, primary=False):
        normal_bg = ACCENT if primary else "#17243a"
        hover_bg = "#38e4ff" if primary else "#223654"
        fg = "#00111a" if primary else TEXT
        button = tk.Button(parent, text=text, command=command, bg=normal_bg, fg=fg,
                           activebackground=hover_bg, activeforeground=fg, relief="flat", bd=0,
                           cursor="hand2", font=(FONT, 11, "bold"), padx=22, pady=12)

        def on_enter(_event):
            button.configure(bg=hover_bg, padx=24, pady=13)

        def on_leave(_event):
            button.configure(bg=normal_bg, padx=22, pady=12)

        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)
        return button

    make_button(actions, "Login", attempt_login, primary=False).pack(side="left")
    make_button(actions, "Login with Certificate", attempt_login, primary=True).pack(side="right")

    tk.Label(card, text="Certificate trust, revocation, replay protection and audit logging are enforced by the existing backend.",
             bg=CARD_BG, fg="#6f8298", font=(FONT, 8)).pack(side="bottom", pady=(0, 8))

    def fade_in(alpha=0.0):
        alpha = min(alpha + 0.08, 1.0)
        login_win.attributes("-alpha", alpha)
        if alpha < 1.0:
            login_win.after(16, lambda: fade_in(alpha))

    fade_in()
    login_win.bind("<Return>", lambda e: attempt_login())
    login_win.bind("<Escape>", lambda e: login_win.destroy() or root.destroy())

    root.wait_window(login_win)
    return authenticated[0]
