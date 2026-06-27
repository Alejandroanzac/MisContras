#!/usr/bin/env python3
"""
Gestor de contraseñas con bóveda cifrada — AES-256-GCM + PBKDF2
Las contraseñas nunca se guardan en texto plano.
"""
import tkinter as tk
from tkinter import messagebox
import json, secrets, random, string, sys
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Cuando corre como .exe (PyInstaller), __file__ apunta a una carpeta temporal.
# sys.executable apunta al .exe real, que es donde queremos guardar el vault.
if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).parent
else:
    APP_DIR = Path(__file__).parent

VAULT_PATH = APP_DIR / "passwords.vault"

# ── Paleta ──────────────────────────────────────────────
BG      = "#0a0c10"
SURFACE = "#111318"
BORDER  = "#1e2230"
ACCENT  = "#00e5ff"
TEXT    = "#e2e8f0"
MUTED   = "#4a5568"
DANGER  = "#ff4444"

# ── Crypto ──────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return kdf.derive(password.encode())

def vault_save(entries: list, password: str):
    salt  = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    ct    = AESGCM(_derive_key(password, salt)).encrypt(nonce, json.dumps(entries, ensure_ascii=False).encode(), None)
    VAULT_PATH.write_bytes(salt + nonce + ct)

def vault_load(password: str) -> list:
    raw = VAULT_PATH.read_bytes()
    pt  = AESGCM(_derive_key(password, raw[:16])).decrypt(raw[16:28], raw[28:], None)
    return json.loads(pt)

# ── Generador ────────────────────────────────────────────

def generar_password(longitud: int = 16, simbolos: bool = True) -> str:
    sym  = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    pool = string.ascii_letters + string.digits + (sym if simbolos else "")
    base = [random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits)]
    if simbolos:
        base.append(random.choice(sym))
    pw = base + [random.choice(pool) for _ in range(longitud - len(base))]
    random.shuffle(pw)
    return "".join(pw)

def calcular_fuerza(pw: str) -> tuple:
    p = sum([any(c.islower() for c in pw), any(c.isupper() for c in pw),
             any(c.isdigit() for c in pw),
             any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pw)])
    if len(pw) >= 20: p += 1
    if len(pw) >= 12: p += 1
    niveles = [("Débil","#ff4444"),("Débil","#ff4444"),("Media","#ffaa00"),
               ("Fuerte","#44aaff"),("Muy fuerte","#44ff88"),("Muy fuerte","#44ff88")]
    return niveles[min(p, 5)]

# ── App ──────────────────────────────────────────────────

class VaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Mis Contras")
        self.geometry("720x540")
        self.minsize(620, 480)
        self.configure(bg=BG)
        try:
            self.iconbitmap(default="")
        except Exception:
            pass

        self._master_pw: str | None = None
        self._entries:   list       = []
        self._show_lock()

    # ── Pantalla de bloqueo ──────────────────────────────

    def _show_lock(self):
        self._clear()

        wrap = tk.Frame(self, bg=BG)
        wrap.place(relx=.5, rely=.5, anchor="center")

        card = tk.Frame(wrap, bg=SURFACE, padx=40, pady=36,
                        highlightthickness=1, highlightbackground=BORDER)
        card.pack()

        tk.Label(card, text="🔐", font=("Segoe UI Emoji", 34),
                 bg=SURFACE, fg=TEXT).pack()
        tk.Label(card, text="Mis Contras", font=("Segoe UI", 18, "bold"),
                 bg=SURFACE, fg=TEXT).pack(pady=(6,2))

        if VAULT_PATH.exists():
            sub = "Ingresa tu contraseña maestra"
        else:
            sub = "Primera vez — crea tu contraseña maestra"

        tk.Label(card, text=sub, font=("Segoe UI", 9),
                 bg=SURFACE, fg=MUTED).pack(pady=(0,18))

        self._pw_var = tk.StringVar()
        pw_entry = tk.Entry(card, textvariable=self._pw_var, show="●",
                            font=("Consolas", 13), bg="#0d0f14", fg=TEXT,
                            insertbackground=TEXT, relief="flat",
                            highlightthickness=1, highlightbackground=BORDER,
                            highlightcolor=ACCENT, width=24)
        pw_entry.pack(ipady=8)
        pw_entry.focus_set()
        pw_entry.bind("<Return>", lambda _: self._unlock())

        self._err_var = tk.StringVar()
        tk.Label(card, textvariable=self._err_var, font=("Segoe UI", 9),
                 bg=SURFACE, fg=DANGER).pack(pady=(6,0))

        tk.Button(card, text="Desbloquear →", font=("Segoe UI", 11, "bold"),
                  bg=ACCENT, fg="#000", activebackground="#00b8cc", activeforeground="#000",
                  relief="flat", padx=22, pady=8, cursor="hand2",
                  command=self._unlock).pack(pady=(14,0))

    def _unlock(self):
        pw = self._pw_var.get()
        if not pw:
            return

        if not VAULT_PATH.exists():
            if len(pw) < 6:
                self._err_var.set("⚠ Mínimo 6 caracteres")
                return
            vault_save([], pw)
            self._master_pw = pw
            self._entries   = []
            self._show_main()
            return

        try:
            self._entries   = vault_load(pw)
            self._master_pw = pw
            self._show_main()
        except Exception:
            self._err_var.set("⚠ Contraseña incorrecta")
            self._pw_var.set("")

    # ── Pantalla principal ───────────────────────────────

    def _show_main(self):
        self._clear()

        # Header
        hdr = tk.Frame(self, bg=SURFACE, padx=18, pady=12,
                       highlightthickness=0)
        hdr.pack(fill="x")

        tk.Label(hdr, text="🔐  Mis Contras", font=("Segoe UI", 13, "bold"),
                 bg=SURFACE, fg=TEXT).pack(side="left")

        right = tk.Frame(hdr, bg=SURFACE)
        right.pack(side="right")

        tk.Button(right, text="+ Agregar", font=("Segoe UI", 9, "bold"),
                  bg=ACCENT, fg="#000", activebackground="#00b8cc", activeforeground="#000",
                  relief="flat", padx=12, pady=4, cursor="hand2",
                  command=self._dialog_agregar).pack(side="left", padx=(0,8))

        tk.Button(right, text="🔒 Bloquear", font=("Segoe UI", 9),
                  bg=SURFACE, fg=MUTED, activebackground=BORDER, activeforeground=TEXT,
                  relief="flat", padx=10, pady=4, cursor="hand2",
                  command=self._lock).pack(side="left")

        # Separador
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # Buscador
        sf = tk.Frame(self, bg=BG, padx=16, pady=10)
        sf.pack(fill="x")

        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._render())

        tk.Entry(sf, textvariable=self._search_var,
                 font=("Segoe UI", 10), bg=SURFACE, fg=TEXT,
                 insertbackground=TEXT, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).pack(fill="x", ipady=7)

        # Área scrollable
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True, padx=16, pady=(0,16))

        self._canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
        sb = tk.Scrollbar(outer, orient="vertical", command=self._canvas.yview)
        self._list = tk.Frame(self._canvas, bg=BG)

        self._list.bind("<Configure>",
                        lambda _: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.create_window((0, 0), window=self._list, anchor="nw")
        self._canvas.configure(yscrollcommand=sb.set)
        self._canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self._canvas.bind_all("<MouseWheel>",
                              lambda e: self._canvas.yview_scroll(-1*(e.delta//120), "units"))

        self._render()

    def _render(self):
        for w in self._list.winfo_children():
            w.destroy()

        q = self._search_var.get().strip().lower() if hasattr(self, "_search_var") else ""
        lista = [(i, e) for i, e in enumerate(self._entries)
                 if q in e["app"].lower()] if q else list(enumerate(self._entries))

        if not lista:
            msg = "Sin resultados." if q else "Bóveda vacía. Pulsa '+ Agregar' para comenzar."
            tk.Label(self._list, text=msg, font=("Segoe UI", 10),
                     bg=BG, fg=MUTED).pack(pady=50)
            return

        for orig_idx, entry in lista:
            self._render_card(entry, orig_idx)

        self._canvas.update_idletasks()
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _render_card(self, entry: dict, orig_idx: int):
        card = tk.Frame(self._list, bg=SURFACE, padx=14, pady=10,
                        highlightthickness=1, highlightbackground=BORDER)
        card.pack(fill="x", pady=(0,6))

        nombre_fuerza, color_fuerza = calcular_fuerza(entry["password"])

        # Fila superior
        top = tk.Frame(card, bg=SURFACE)
        top.pack(fill="x")
        tk.Label(top, text=entry["app"], font=("Segoe UI", 11, "bold"),
                 bg=SURFACE, fg=TEXT).pack(side="left")
        tk.Label(top, text=f"  {nombre_fuerza}", font=("Segoe UI", 8, "bold"),
                 bg=SURFACE, fg=color_fuerza).pack(side="left")
        tk.Label(top, text=entry.get("fecha",""), font=("Segoe UI", 8),
                 bg=SURFACE, fg=MUTED).pack(side="right")

        if entry.get("usuario"):
            tk.Label(card, text=f"👤  {entry['usuario']}", font=("Segoe UI", 9),
                     bg=SURFACE, fg=MUTED).pack(anchor="w", pady=(4,0))

        # Fila de contraseña
        pw_frame = tk.Frame(card, bg="#0d0f14", padx=10, pady=6,
                            highlightthickness=1, highlightbackground=BORDER)
        pw_frame.pack(fill="x", pady=(8,6))

        visible = [False]
        pw_var  = tk.StringVar(value="●" * len(entry["password"]))

        tk.Label(pw_frame, textvariable=pw_var, font=("Consolas", 11),
                 bg="#0d0f14", fg=TEXT, anchor="w").pack(side="left", fill="x", expand=True)

        def toggle(e=entry, pv=pw_var, vis=visible):
            vis[0] = not vis[0]
            pv.set(e["password"] if vis[0] else "●" * len(e["password"]))

        # Botones
        btns = tk.Frame(card, bg=SURFACE)
        btns.pack(fill="x")

        tk.Button(btns, text="👁  Ver", font=("Segoe UI", 8, "bold"),
                  bg=BORDER, fg=TEXT, activebackground="#2a313d", activeforeground=TEXT,
                  relief="flat", padx=10, pady=3, cursor="hand2",
                  command=toggle).pack(side="left", padx=(0,6))

        def copiar(e=entry):
            self.clipboard_clear()
            self.clipboard_append(e["password"])
            self.after(2000, self.clipboard_clear)

        tk.Button(btns, text="📋  Copiar", font=("Segoe UI", 8, "bold"),
                  bg=ACCENT, fg="#000", activebackground="#00b8cc", activeforeground="#000",
                  relief="flat", padx=10, pady=3, cursor="hand2",
                  command=copiar).pack(side="left", padx=(0,6))

        def eliminar(idx=orig_idx):
            if messagebox.askyesno("Eliminar",
                                   f"¿Eliminar la contra de '{self._entries[idx]['app']}'?"):
                self._entries.pop(idx)
                vault_save(self._entries, self._master_pw)
                self._render()

        tk.Button(btns, text="🗑", font=("Segoe UI", 10),
                  bg=SURFACE, fg=DANGER, activebackground=BORDER, activeforeground=DANGER,
                  relief="flat", padx=8, pady=2, cursor="hand2",
                  command=eliminar).pack(side="right")

    # ── Diálogo agregar ──────────────────────────────────

    def _dialog_agregar(self):
        dlg = tk.Toplevel(self)
        dlg.title("Nueva entrada")
        dlg.configure(bg=BG)
        dlg.geometry("440x390")
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.transient(self)

        tk.Label(dlg, text="Nueva contraseña", font=("Segoe UI", 13, "bold"),
                 bg=BG, fg=TEXT).pack(pady=(20,2))
        tk.Label(dlg, text="Completa los campos o genera una contraseña automática.",
                 font=("Segoe UI", 9), bg=BG, fg=MUTED).pack(pady=(0,16))

        form = tk.Frame(dlg, bg=BG, padx=28)
        form.pack(fill="x")

        def campo(label: str) -> tk.Entry:
            tk.Label(form, text=label, font=("Segoe UI", 9),
                     bg=BG, fg=MUTED, anchor="w").pack(fill="x")
            e = tk.Entry(form, font=("Segoe UI", 10), bg=SURFACE, fg=TEXT,
                         insertbackground=TEXT, relief="flat",
                         highlightthickness=1, highlightbackground=BORDER,
                         highlightcolor=ACCENT)
            e.pack(fill="x", ipady=7, pady=(2,10))
            return e

        e_app  = campo("Aplicación  *")
        e_user = campo("Usuario / Email  (opcional)")

        tk.Label(form, text="Contraseña  *", font=("Segoe UI", 9),
                 bg=BG, fg=MUTED, anchor="w").pack(fill="x")

        pw_row = tk.Frame(form, bg=BG)
        pw_row.pack(fill="x", pady=(2,10))

        e_pw = tk.Entry(pw_row, font=("Consolas", 10), bg=SURFACE, fg=TEXT,
                        insertbackground=TEXT, relief="flat",
                        highlightthickness=1, highlightbackground=BORDER,
                        highlightcolor=ACCENT)
        e_pw.pack(side="left", fill="x", expand=True, ipady=7)

        def generar():
            e_pw.delete(0, "end")
            e_pw.insert(0, generar_password(16, True))

        tk.Button(pw_row, text="⚡ Generar", font=("Segoe UI", 8, "bold"),
                  bg=ACCENT, fg="#000", activebackground="#00b8cc", activeforeground="#000",
                  relief="flat", padx=8, pady=7, cursor="hand2",
                  command=generar).pack(side="left", padx=(6,0))

        def guardar():
            app = e_app.get().strip()
            pw  = e_pw.get().strip()
            if not app or not pw:
                messagebox.showwarning("Faltan datos",
                                       "App y contraseña son obligatorios.", parent=dlg)
                return
            nombre_fuerza, _ = calcular_fuerza(pw)
            self._entries.insert(0, {
                "app":      app,
                "usuario":  e_user.get().strip(),
                "password": pw,
                "fuerza":   nombre_fuerza,
                "longitud": len(pw),
                "fecha":    datetime.now().strftime("%d/%m/%Y %H:%M"),
            })
            vault_save(self._entries, self._master_pw)
            dlg.destroy()
            self._render()

        tk.Button(dlg, text="Guardar →", font=("Segoe UI", 11, "bold"),
                  bg=ACCENT, fg="#000", activebackground="#00b8cc", activeforeground="#000",
                  relief="flat", padx=22, pady=8, cursor="hand2",
                  command=guardar).pack(pady=(4,0))

        e_pw.bind("<Return>", lambda _: guardar())

    # ── Utils ────────────────────────────────────────────

    def _lock(self):
        self._master_pw = None
        self._entries   = []
        self._show_lock()

    def _clear(self):
        for w in self.winfo_children():
            w.destroy()


if __name__ == "__main__":
    VaultApp().mainloop()
