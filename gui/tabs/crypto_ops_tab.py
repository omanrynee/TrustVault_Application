"""
Cryptographic Operations Tab — TrustVault
=============================================
Provides a unified GUI panel for:
  - File signing (RSA-PSS / ECDSA)
  - Signature verification
  - File encryption (AES-256-GCM + RSA-OAEP)
  - File decryption
  - Message signing / verification
  - Message encryption / decryption
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import threading
from config import constants


class CryptoOpsTab:
    """GUI tab providing all digital-signature and hybrid-encryption operations."""

    def __init__(self, parent, app):
        self.parent = parent
        self.app    = app
        self.t      = constants.THEMES[app.config.get("theme", constants.DEFAULT_THEME)]

        self.frame = tk.Frame(parent, bg=self.t["bg"])
        self._build_ui()
        self.frame.pack(fill="both", expand=True)

    # ─────────────────────────────────────────────────────────────────────────
    # Layout
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        t = self.t

        tk.Label(
            self.frame,
            text="🔏 Cryptographic Operations",
            font=("Segoe UI", 18, "bold"),
            fg=t["fg"], bg=t["bg"],
        ).pack(pady=(18, 0))

        tk.Label(
            self.frame,
            text="Digital Signatures (RSA-PSS / ECDSA) · Hybrid Encryption (AES-256-GCM + RSA-OAEP)",
            font=("Segoe UI", 10),
            fg="#888888", bg=t["bg"],
        ).pack(pady=(0, 10))

        nb = ttk.Notebook(self.frame)
        nb.pack(fill="both", expand=True, padx=10, pady=5)

        # Sub-tabs
        self._build_sign_tab(nb)
        self._build_verify_tab(nb)
        self._build_encrypt_tab(nb)
        self._build_decrypt_tab(nb)
        self._build_message_tab(nb)

    # ─────────────────────────────────────────────────────────────────────────
    # Tab 1 — File Signing
    # ─────────────────────────────────────────────────────────────────────────

    def _build_sign_tab(self, nb):
        t = self.t
        frame = tk.Frame(nb, bg=t["bg"])
        nb.add(frame, text="✍️ Sign File")

        tk.Label(frame, text="✍️ Sign a File", font=("Segoe UI", 14, "bold"),
                 fg=t["fg"], bg=t["bg"]).pack(pady=15)

        # File to sign
        self.sign_file_var = tk.StringVar()
        self._row(frame, "File to sign:", self.sign_file_var,
                  btn_text="Browse…", btn_cmd=lambda: self._browse(self.sign_file_var))

        # Private key
        self.sign_key_var = tk.StringVar()
        self._row(frame, "Private key (.key / .p12):", self.sign_key_var,
                  btn_text="Browse…", btn_cmd=lambda: self._browse(self.sign_key_var))

        # Key password
        self.sign_pass_var = tk.StringVar()
        self._row(frame, "Key password (optional):", self.sign_pass_var, show="●")

        # Algorithm
        algo_frame = tk.Frame(frame, bg=t["bg"])
        algo_frame.pack(fill="x", padx=30, pady=6)
        tk.Label(algo_frame, text="Algorithm:", fg=t["fg"], bg=t["bg"],
                 width=26, anchor="w", font=("Segoe UI", 11)).pack(side="left")
        self.sign_algo_var = tk.StringVar(value="RSA-PSS")
        for algo in ("RSA-PSS", "ECDSA"):
            tk.Radiobutton(
                algo_frame, text=algo, variable=self.sign_algo_var, value=algo,
                fg=t["fg"], bg=t["bg"], selectcolor=t["bg"],
                activeforeground=t["fg"], activebackground=t["bg"],
                font=("Segoe UI", 11),
            ).pack(side="left", padx=10)

        # Action
        tk.Button(
            frame, text="🔏 Sign File", command=self._do_sign,
            bg="#27ae60", fg="white", font=("Segoe UI", 12, "bold"), padx=20, pady=8,
        ).pack(pady=15)

        self.sign_output = self._output_box(frame)

    # ─────────────────────────────────────────────────────────────────────────
    # Tab 2 — Signature Verification
    # ─────────────────────────────────────────────────────────────────────────

    def _build_verify_tab(self, nb):
        t = self.t
        frame = tk.Frame(nb, bg=t["bg"])
        nb.add(frame, text="✅ Verify Signature")

        tk.Label(frame, text="✅ Verify a File Signature", font=("Segoe UI", 14, "bold"),
                 fg=t["fg"], bg=t["bg"]).pack(pady=15)

        self.ver_file_var = tk.StringVar()
        self._row(frame, "Signed file:", self.ver_file_var,
                  btn_text="Browse…", btn_cmd=lambda: self._browse(self.ver_file_var))

        self.ver_cert_var = tk.StringVar()
        self._row(frame, "Certificate / public key:", self.ver_cert_var,
                  btn_text="Browse…", btn_cmd=lambda: self._browse(self.ver_cert_var))

        self.ver_sig_var = tk.StringVar()
        self._row(frame, "Signature file (.sig):", self.ver_sig_var,
                  btn_text="Browse…", btn_cmd=lambda: self._browse(self.ver_sig_var))

        tk.Button(
            frame, text="🔍 Verify Signature", command=self._do_verify,
            bg="#2980b9", fg="white", font=("Segoe UI", 12, "bold"), padx=20, pady=8,
        ).pack(pady=15)

        self.ver_output = self._output_box(frame)

    # ─────────────────────────────────────────────────────────────────────────
    # Tab 3 — File Encryption
    # ─────────────────────────────────────────────────────────────────────────

    def _build_encrypt_tab(self, nb):
        t = self.t
        frame = tk.Frame(nb, bg=t["bg"])
        nb.add(frame, text="🔒 Encrypt File")

        tk.Label(frame, text="🔒 Encrypt a File (AES-256-GCM + RSA-OAEP)", font=("Segoe UI", 14, "bold"),
                 fg=t["fg"], bg=t["bg"]).pack(pady=15)

        self.enc_file_var = tk.StringVar()
        self._row(frame, "File to encrypt:", self.enc_file_var,
                  btn_text="Browse…", btn_cmd=lambda: self._browse(self.enc_file_var))

        self.enc_cert_var = tk.StringVar()
        self._row(frame, "Recipient certificate / pubkey:", self.enc_cert_var,
                  btn_text="Browse…", btn_cmd=lambda: self._browse(self.enc_cert_var))

        tk.Button(
            frame, text="🔒 Encrypt File", command=self._do_encrypt,
            bg="#8e44ad", fg="white", font=("Segoe UI", 12, "bold"), padx=20, pady=8,
        ).pack(pady=15)

        self.enc_output = self._output_box(frame)

    # ─────────────────────────────────────────────────────────────────────────
    # Tab 4 — File Decryption
    # ─────────────────────────────────────────────────────────────────────────

    def _build_decrypt_tab(self, nb):
        t = self.t
        frame = tk.Frame(nb, bg=t["bg"])
        nb.add(frame, text="🔓 Decrypt File")

        tk.Label(frame, text="🔓 Decrypt a File", font=("Segoe UI", 14, "bold"),
                 fg=t["fg"], bg=t["bg"]).pack(pady=15)

        self.dec_file_var = tk.StringVar()
        self._row(frame, "Encrypted file (.enc):", self.dec_file_var,
                  btn_text="Browse…", btn_cmd=lambda: self._browse(self.dec_file_var))

        self.dec_key_var = tk.StringVar()
        self._row(frame, "Private key (.key / .p12):", self.dec_key_var,
                  btn_text="Browse…", btn_cmd=lambda: self._browse(self.dec_key_var))

        self.dec_pass_var = tk.StringVar()
        self._row(frame, "Key password (optional):", self.dec_pass_var, show="●")

        tk.Button(
            frame, text="🔓 Decrypt File", command=self._do_decrypt,
            bg="#e67e22", fg="white", font=("Segoe UI", 12, "bold"), padx=20, pady=8,
        ).pack(pady=15)

        self.dec_output = self._output_box(frame)

    # ─────────────────────────────────────────────────────────────────────────
    # Tab 5 — Message Operations
    # ─────────────────────────────────────────────────────────────────────────

    def _build_message_tab(self, nb):
        t = self.t
        frame = tk.Frame(nb, bg=t["bg"])
        nb.add(frame, text="💬 Message Crypto")

        tk.Label(frame, text="💬 Sign / Verify / Encrypt / Decrypt Messages",
                 font=("Segoe UI", 14, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=10)

        # Message input
        tk.Label(frame, text="Message:", fg=t["fg"], bg=t["bg"],
                 font=("Segoe UI", 11), anchor="w").pack(fill="x", padx=30)
        self.msg_text = tk.Text(frame, height=4, bg=t["entry_bg"], fg=t["fg"],
                                font=("Segoe UI", 11), relief="flat", padx=8, pady=8)
        self.msg_text.pack(fill="x", padx=30, pady=(0, 8))

        # Key fields
        self.msg_key_var  = tk.StringVar()
        self.msg_pass_var = tk.StringVar()
        self.msg_cert_var = tk.StringVar()
        self._row(frame, "Private key (.key / .p12):", self.msg_key_var,
                  btn_text="Browse…", btn_cmd=lambda: self._browse(self.msg_key_var))
        self._row(frame, "Key password (optional):", self.msg_pass_var, show="●")
        self._row(frame, "Certificate / pubkey (for encrypt/verify):", self.msg_cert_var,
                  btn_text="Browse…", btn_cmd=lambda: self._browse(self.msg_cert_var))

        # Algorithm
        self.msg_algo_var = tk.StringVar(value="RSA-PSS")
        algo_frame = tk.Frame(frame, bg=t["bg"])
        algo_frame.pack(fill="x", padx=30, pady=4)
        tk.Label(algo_frame, text="Signature algorithm:", fg=t["fg"], bg=t["bg"],
                 width=26, anchor="w", font=("Segoe UI", 11)).pack(side="left")
        for algo in ("RSA-PSS", "ECDSA"):
            tk.Radiobutton(
                algo_frame, text=algo, variable=self.msg_algo_var, value=algo,
                fg=t["fg"], bg=t["bg"], selectcolor=t["bg"],
                activeforeground=t["fg"], activebackground=t["bg"],
                font=("Segoe UI", 11),
            ).pack(side="left", padx=8)

        # Signature field (for verify)
        tk.Label(frame, text="Signature / Ciphertext (paste here for verify/decrypt):",
                 fg=t["fg"], bg=t["bg"], font=("Segoe UI", 10), anchor="w").pack(fill="x", padx=30)
        self.msg_sig_text = tk.Text(frame, height=3, bg=t["entry_bg"], fg=t["fg"],
                                    font=("Segoe UI", 9), relief="flat", padx=8, pady=4)
        self.msg_sig_text.pack(fill="x", padx=30, pady=(0, 8))

        # Buttons
        btn_frame = tk.Frame(frame, bg=t["bg"])
        btn_frame.pack(pady=8)
        for label, color, cmd in [
            ("✍️ Sign",        "#27ae60", self._do_msg_sign),
            ("✅ Verify",       "#2980b9", self._do_msg_verify),
            ("🔒 Encrypt",     "#8e44ad", self._do_msg_encrypt),
            ("🔓 Decrypt",     "#e67e22", self._do_msg_decrypt),
        ]:
            tk.Button(btn_frame, text=label, command=cmd,
                      bg=color, fg="white", font=("Segoe UI", 11, "bold"),
                      padx=12, pady=6).pack(side="left", padx=6)

        self.msg_output = self._output_box(frame, height=6)

    # ─────────────────────────────────────────────────────────────────────────
    # Action handlers
    # ─────────────────────────────────────────────────────────────────────────

    def _do_sign(self):
        filepath = self.sign_file_var.get().strip()
        key_path = self.sign_key_var.get().strip()
        password = self.sign_pass_var.get().strip() or None
        algo     = self.sign_algo_var.get()

        if not filepath or not key_path:
            messagebox.showwarning("Missing Input", "Please select a file and a private key.")
            return

        self._run_async(
            lambda: __import__("security.signing", fromlist=["sign_file"]).sign_file(
                filepath, key_path, password=password, algorithm=algo),
            self.sign_output,
        )

    def _do_verify(self):
        filepath  = self.ver_file_var.get().strip()
        cert_path = self.ver_cert_var.get().strip()
        sig_path  = self.ver_sig_var.get().strip() or None

        if not filepath or not cert_path:
            messagebox.showwarning("Missing Input", "Please select the file and its certificate.")
            return

        self._run_async(
            lambda: __import__("security.signing", fromlist=["verify_file"]).verify_file(
                filepath, cert_path, sig_path),
            self.ver_output,
        )

    def _do_encrypt(self):
        filepath  = self.enc_file_var.get().strip()
        cert_path = self.enc_cert_var.get().strip()

        if not filepath or not cert_path:
            messagebox.showwarning("Missing Input", "Please select a file and a recipient certificate.")
            return

        self._run_async(
            lambda: __import__("security.encryption", fromlist=["encrypt_file"]).encrypt_file(
                filepath, cert_path),
            self.enc_output,
        )

    def _do_decrypt(self):
        enc_path = self.dec_file_var.get().strip()
        key_path = self.dec_key_var.get().strip()
        password = self.dec_pass_var.get().strip() or None

        if not enc_path or not key_path:
            messagebox.showwarning("Missing Input", "Please select an encrypted file and a private key.")
            return

        self._run_async(
            lambda: __import__("security.encryption", fromlist=["decrypt_file"]).decrypt_file(
                enc_path, key_path, password=password),
            self.dec_output,
        )

    def _do_msg_sign(self):
        message  = self.msg_text.get("1.0", "end").strip()
        key_path = self.msg_key_var.get().strip()
        password = self.msg_pass_var.get().strip() or None
        algo     = self.msg_algo_var.get()

        if not message or not key_path:
            messagebox.showwarning("Missing Input", "Please enter a message and select a private key.")
            return

        def _run():
            from security.signing import sign_message
            ok, result = sign_message(message, key_path, password=password, algorithm=algo)
            if ok:
                self.msg_sig_text.delete("1.0", "end")
                self.msg_sig_text.insert("1.0", result)
            return ok, f"Signature:\n{result}" if ok else result

        self._run_async(_run, self.msg_output)

    def _do_msg_verify(self):
        message   = self.msg_text.get("1.0", "end").strip()
        cert_path = self.msg_cert_var.get().strip()
        sig_b64   = self.msg_sig_text.get("1.0", "end").strip()
        algo      = self.msg_algo_var.get()

        if not message or not cert_path or not sig_b64:
            messagebox.showwarning("Missing Input",
                                   "Please enter a message, select a certificate, and paste the signature.")
            return

        self._run_async(
            lambda: __import__("security.signing", fromlist=["verify_message"]).verify_message(
                message, cert_path, sig_b64, algorithm=algo),
            self.msg_output,
        )

    def _do_msg_encrypt(self):
        message   = self.msg_text.get("1.0", "end").strip()
        cert_path = self.msg_cert_var.get().strip()

        if not message or not cert_path:
            messagebox.showwarning("Missing Input", "Please enter a message and select a recipient certificate.")
            return

        def _run():
            from security.encryption import encrypt_message
            ok, result = encrypt_message(message, cert_path)
            if ok:
                self.msg_sig_text.delete("1.0", "end")
                self.msg_sig_text.insert("1.0", result)
            return ok, f"Encrypted:\n{result[:120]}…" if ok else result

        self._run_async(_run, self.msg_output)

    def _do_msg_decrypt(self):
        env_b64  = self.msg_sig_text.get("1.0", "end").strip()
        key_path = self.msg_key_var.get().strip()
        password = self.msg_pass_var.get().strip() or None

        if not env_b64 or not key_path:
            messagebox.showwarning("Missing Input",
                                   "Please paste the encrypted message and select your private key.")
            return

        def _run():
            from security.encryption import decrypt_message
            ok, result = decrypt_message(env_b64, key_path, password=password)
            if ok:
                self.msg_text.delete("1.0", "end")
                self.msg_text.insert("1.0", result)
            return ok, f"Decrypted message:\n{result}" if ok else result

        self._run_async(_run, self.msg_output)

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _run_async(self, fn, output_widget):
        """Run *fn* in a background thread; display result in *output_widget*."""
        def _worker():
            try:
                ok, msg = fn()
                colour = "#00ff88" if ok else "#ff4444"
                self.frame.after(0, lambda: self._set_output(output_widget, msg, colour))
            except Exception as exc:
                self.frame.after(0, lambda: self._set_output(
                    output_widget, f"Unexpected error: {exc}", "#ff4444"))

        threading.Thread(target=_worker, daemon=True).start()

    def _set_output(self, widget, text, colour="#00ffcc"):
        widget.config(state="normal", fg=colour)
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.config(state="disabled")

    def _row(self, parent, label, var, btn_text=None, btn_cmd=None, show=None):
        t = self.t
        row = tk.Frame(parent, bg=t["bg"])
        row.pack(fill="x", padx=30, pady=5)
        tk.Label(row, text=label, fg=t["fg"], bg=t["bg"],
                 font=("Segoe UI", 11), width=36, anchor="w").pack(side="left")
        kw = {"show": show} if show else {}
        entry = tk.Entry(row, textvariable=var, width=38,
                         bg=t["entry_bg"], fg=t["fg"],
                         font=("Segoe UI", 11), **kw)
        entry.pack(side="left", padx=6)
        if btn_text:
            tk.Button(row, text=btn_text, command=btn_cmd,
                      bg=t["btn"], fg=t["btn_fg"],
                      font=("Segoe UI", 10), padx=8).pack(side="left")

    def _output_box(self, parent, height=5):
        t   = self.t
        box = scrolledtext.ScrolledText(
            parent, height=height, state="disabled",
            bg=t["text_bg"], fg="#00ffcc",
            font=("Segoe UI", 10), relief="flat",
        )
        box.pack(fill="x", padx=30, pady=(5, 15))
        return box

    def _browse(self, var):
        path = filedialog.askopenfilename()
        if path:
            var.set(path)
