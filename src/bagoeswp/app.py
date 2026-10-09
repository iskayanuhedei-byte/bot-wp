from __future__ import annotations

import json
import os
import queue
import threading
import tkinter as tk
import traceback
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from bagoeswp import __version__
from bagoeswp.models import AuthMethod, JobResult, JobStatus, ServerConfig, SiteSpec
from bagoeswp.orchestrator import BulkInstaller, summarize_results
from bagoeswp.validation import (
    ValidationError,
    parse_bulk_text,
    read_sites_csv,
    validate_domain,
    validate_server,
    validate_sites,
)


BG = "#0b1220"
PANEL = "#111b2e"
PANEL_ALT = "#17243a"
TEXT = "#e8eef8"
MUTED = "#93a4bd"
ACCENT = "#3b82f6"
SUCCESS = "#22c55e"
WARNING = "#f59e0b"
DANGER = "#ef4444"


def app_log_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    path = base / "BagoesWP" / "logs" / "app.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_app_exception(exc_type: type[BaseException], exc: BaseException, tb: object) -> Path:
    path = app_log_path()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"\n[{datetime.now().isoformat(timespec='seconds')}] {exc_type.__name__}: {exc}\n")
        handle.write("".join(traceback.format_exception(exc_type, exc, tb)))
    return path


class BulkInputDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent)
        self.title("Tambah Domain Massal")
        self.geometry("900x520")
        self.configure(bg=BG)
        self.transient(parent)
        self.grab_set()
        self.result: list[SiteSpec] | None = None

        ttk.Label(
            self,
            text="Satu domain per baris",
            style="Title.TLabel",
        ).pack(anchor="w", padx=20, pady=(18, 4))
        ttk.Label(
            self,
            text="domain | judul | admin_user | email | password | locale | ssl | www",
            style="Muted.TLabel",
        ).pack(anchor="w", padx=20, pady=(0, 10))
        self.text = tk.Text(
            self,
            bg="#08101d",
            fg=TEXT,
            insertbackground=TEXT,
            selectbackground=ACCENT,
            relief="flat",
            font=("Consolas", 10),
            padx=12,
            pady=12,
            wrap="none",
        )
        self.text.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        self.text.insert(
            "1.0",
            "example.com|Example Site|siteadmin|admin@example.com|GantiPasswordKuat123!|en_US|true|true",
        )
        footer = ttk.Frame(self, style="Panel.TFrame")
        footer.pack(fill="x", padx=20, pady=(0, 18))
        ttk.Button(footer, text="Batal", command=self.destroy).pack(side="right")
        ttk.Button(footer, text="Tambahkan", style="Accent.TButton", command=self._accept).pack(
            side="right", padx=(0, 8)
        )

    def _accept(self) -> None:
        try:
            self.result = parse_bulk_text(self.text.get("1.0", "end"))
        except ValidationError as exc:
            messagebox.showerror("Data tidak valid", str(exc), parent=self)
            return
        self.destroy()


class BagoesWPApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"BagoesWP OLS Manager v{__version__}")
        self.geometry("1380x850")
        self.minsize(1120, 720)
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.report_callback_exception = self._handle_tk_exception

        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.sites: list[SiteSpec] = []
        self.results: list[JobResult] = []
        self.installer: BulkInstaller | None = None
        self.worker: threading.Thread | None = None
        self._busy = False

        self._configure_styles()
        self._build_ui()
        self.after(100, self._drain_events)
        self.after(150, self._bring_to_front)

    def _bring_to_front(self) -> None:
        self.deiconify()
        self.lift()
        self.attributes("-topmost", True)
        self.focus_force()
        self.after(600, lambda: self.attributes("-topmost", False))

    def _handle_tk_exception(
        self,
        exc_type: type[BaseException],
        exc: BaseException,
        tb: object,
    ) -> None:
        path = write_app_exception(exc_type, exc, tb)
        messagebox.showerror(
            "BagoesWP mengalami error",
            f"Detail error disimpan di:\n{path}",
            parent=self,
        )

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("Alt.TFrame", background=PANEL_ALT)
        style.configure("TLabel", background=PANEL, foreground=TEXT)
        style.configure("Title.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI Semibold", 15))
        style.configure("Header.TLabel", background=BG, foreground=TEXT, font=("Segoe UI Semibold", 22))
        style.configure("Muted.TLabel", background=PANEL, foreground=MUTED)
        style.configure("Status.TLabel", background=BG, foreground=MUTED)
        style.configure("TEntry", fieldbackground="#0c1627", foreground=TEXT, insertcolor=TEXT, borderwidth=0)
        style.configure("TCombobox", fieldbackground="#0c1627", foreground=TEXT, arrowcolor=TEXT)
        style.map("TCombobox", fieldbackground=[("readonly", "#0c1627")], foreground=[("readonly", TEXT)])
        style.configure("TSpinbox", fieldbackground="#0c1627", foreground=TEXT)
        style.configure("TCheckbutton", background=PANEL, foreground=TEXT)
        style.map("TCheckbutton", background=[("active", PANEL)], foreground=[("active", TEXT)])
        style.configure("TButton", background=PANEL_ALT, foreground=TEXT, padding=(13, 8), borderwidth=0)
        style.map("TButton", background=[("active", "#223552"), ("disabled", "#182235")])
        style.configure("Accent.TButton", background=ACCENT, foreground="white", padding=(16, 9))
        style.map("Accent.TButton", background=[("active", "#2563eb"), ("disabled", "#244a7d")])
        style.configure("Danger.TButton", background="#7f1d1d", foreground="white", padding=(13, 8))
        style.configure(
            "Treeview",
            background="#0c1627",
            fieldbackground="#0c1627",
            foreground=TEXT,
            rowheight=30,
            borderwidth=0,
        )
        style.configure("Treeview.Heading", background=PANEL_ALT, foreground=TEXT, relief="flat")
        style.map("Treeview", background=[("selected", "#1d4ed8")])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL_ALT, foreground=MUTED, padding=(14, 8))
        style.map("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", TEXT)])

    def _build_ui(self) -> None:
        header = ttk.Frame(self, style="Panel.TFrame")
        header.pack(fill="x", padx=18, pady=(16, 10))
        title_box = ttk.Frame(header, style="Panel.TFrame")
        title_box.pack(side="left", padx=18, pady=13)
        ttk.Label(title_box, text="BagoesWP OLS Manager", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            title_box,
            text="Bulk WordPress • OLS • benchmark • tuning adaptif • cleanup otomatis",
            style="Muted.TLabel",
        ).pack(anchor="w")
        self.header_status = ttk.Label(header, text="Siap", style="Muted.TLabel")
        self.header_status.pack(side="right", padx=18)

        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=18, pady=(0, 10))
        left = ttk.Frame(body, style="Panel.TFrame", width=380)
        right = ttk.Frame(body, style="Panel.TFrame")
        body.add(left, weight=0)
        body.add(right, weight=1)
        self._build_server_panel(left)
        self._build_sites_panel(right)

        log_panel = ttk.Frame(self, style="Panel.TFrame")
        log_panel.pack(fill="both", padx=18, pady=(0, 16))
        ttk.Label(log_panel, text="Log proses", style="Title.TLabel").pack(anchor="w", padx=14, pady=(10, 5))
        self.log_text = tk.Text(
            log_panel,
            height=9,
            bg="#070d17",
            fg="#c7d2e3",
            insertbackground=TEXT,
            relief="flat",
            font=("Consolas", 9),
            state="disabled",
            padx=10,
            pady=8,
        )
        self.log_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_server_panel(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Koneksi VPS", style="Title.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(16, 12)
        )
        self.host_var = tk.StringVar()
        self.port_var = tk.StringVar(value="22")
        self.user_var = tk.StringVar(value="root")
        self.auth_var = tk.StringVar(value="Otomatis")
        self.password_var = tk.StringVar()
        self.key_var = tk.StringVar()
        self.passphrase_var = tk.StringVar()
        self.sudo_var = tk.StringVar()
        self.concurrent_var = tk.StringVar(value="10")
        self.prepare_var = tk.BooleanVar(value=True)

        fields = [
            ("IP / Host", self.host_var, False),
            ("Port SSH", self.port_var, False),
            ("Username", self.user_var, False),
        ]
        row = 1
        for label, variable, secret in fields:
            ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=16, pady=6)
            ttk.Entry(parent, textvariable=variable, show="*" if secret else "").grid(
                row=row, column=1, sticky="ew", padx=(6, 16), pady=6
            )
            row += 1
        ttk.Label(parent, text="Autentikasi").grid(row=row, column=0, sticky="w", padx=16, pady=6)
        auth = ttk.Combobox(
            parent,
            textvariable=self.auth_var,
            values=("Otomatis", "Password", "OpenSSH Key", "PPK", "SSH Agent/Pageant"),
            state="readonly",
        )
        auth.grid(row=row, column=1, sticky="ew", padx=(6, 16), pady=6)
        auth.bind("<<ComboboxSelected>>", lambda _event: self._update_auth_fields())
        row += 1

        ttk.Label(parent, text="Password SSH").grid(row=row, column=0, sticky="w", padx=16, pady=6)
        self.password_entry = ttk.Entry(parent, textvariable=self.password_var, show="•")
        self.password_entry.grid(row=row, column=1, sticky="ew", padx=(6, 16), pady=6)
        row += 1

        ttk.Label(parent, text="Private key").grid(row=row, column=0, sticky="w", padx=16, pady=6)
        key_row = ttk.Frame(parent, style="Panel.TFrame")
        key_row.grid(row=row, column=1, sticky="ew", padx=(6, 16), pady=6)
        key_row.columnconfigure(0, weight=1)
        self.key_entry = ttk.Entry(key_row, textvariable=self.key_var)
        self.key_entry.grid(row=0, column=0, sticky="ew")
        self.key_button = ttk.Button(key_row, text="…", width=3, command=self._choose_key)
        self.key_button.grid(row=0, column=1, padx=(5, 0))
        row += 1

        ttk.Label(parent, text="Key passphrase").grid(row=row, column=0, sticky="w", padx=16, pady=6)
        self.passphrase_entry = ttk.Entry(parent, textvariable=self.passphrase_var, show="•")
        self.passphrase_entry.grid(row=row, column=1, sticky="ew", padx=(6, 16), pady=6)
        row += 1

        ttk.Label(parent, text="Password sudo").grid(row=row, column=0, sticky="w", padx=16, pady=6)
        ttk.Entry(parent, textvariable=self.sudo_var, show="•").grid(
            row=row, column=1, sticky="ew", padx=(6, 16), pady=6
        )
        row += 1

        ttk.Label(parent, text="Concurrency").grid(row=row, column=0, sticky="w", padx=16, pady=6)
        ttk.Spinbox(parent, from_=1, to=10, textvariable=self.concurrent_var, width=8).grid(
            row=row, column=1, sticky="w", padx=(6, 16), pady=6
        )
        row += 1
        ttk.Checkbutton(parent, text="Siapkan stack server satu kali", variable=self.prepare_var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=16, pady=(8, 4)
        )
        row += 1
        ttk.Label(
            parent,
            text="Cleanup aman dan system WP-Cron dipasang otomatis.",
            style="Muted.TLabel",
            wraplength=330,
        ).grid(row=row, column=0, columnspan=2, sticky="w", padx=16, pady=(2, 4))
        row += 1
        ttk.Label(
            parent,
            text=(
                "Ubuntu cloud biasanya memakai username ubuntu. "
                "PPK dibaca langsung; PuTTYgen tidak diperlukan. "
                "Passphrase key berbeda dari Password sudo. "
                "Kredensial lain yang terisi dapat dipakai sebagai fallback."
            ),
            style="Muted.TLabel",
            wraplength=330,
        ).grid(row=row, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 12))
        row += 1
        self.test_button = ttk.Button(parent, text="Tes Koneksi", command=self._test_connection)
        self.test_button.grid(row=row, column=0, columnspan=2, sticky="ew", padx=16, pady=(4, 16))
        parent.columnconfigure(1, weight=1)
        self._update_auth_fields()

    def _build_sites_panel(self, parent: ttk.Frame) -> None:
        toolbar = ttk.Frame(parent, style="Panel.TFrame")
        toolbar.pack(fill="x", padx=14, pady=(14, 8))
        ttk.Label(toolbar, text="Domain WordPress", style="Title.TLabel").pack(side="left")
        self.import_button = ttk.Button(toolbar, text="Impor CSV", command=self._import_csv)
        self.import_button.pack(side="right")
        self.bulk_add_button = ttk.Button(toolbar, text="Tambah Massal", command=self._bulk_add)
        self.bulk_add_button.pack(side="right", padx=(0, 7))
        self.remove_list_button = ttk.Button(
            toolbar, text="Hapus dari Daftar", command=self._remove_selected
        )
        self.remove_list_button.pack(side="right", padx=(0, 7))

        columns = ("domain", "title", "admin", "locale", "ssl", "status", "message")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="extended")
        headings = {
            "domain": "Domain",
            "title": "Judul",
            "admin": "Admin",
            "locale": "Locale",
            "ssl": "SSL",
            "status": "Status",
            "message": "Keterangan",
        }
        widths = {"domain": 180, "title": 150, "admin": 100, "locale": 65, "ssl": 45, "status": 145, "message": 260}
        for key in columns:
            self.tree.heading(key, text=headings[key])
            self.tree.column(key, width=widths[key], minwidth=45, stretch=key in {"domain", "title", "message"})
        self.tree.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        self.tree.tag_configure(JobStatus.VERIFIED.value, foreground="#86efac")
        self.tree.tag_configure(JobStatus.OPTIMAL.value, foreground="#34d399")
        self.tree.tag_configure(JobStatus.INSTALLED.value, foreground="#c4b5fd")
        self.tree.tag_configure(JobStatus.FAILED.value, foreground="#fca5a5")
        self.tree.tag_configure(JobStatus.INSTALLED_PENDING_SSL.value, foreground="#fcd34d")
        self.tree.tag_configure(JobStatus.RUNNING.value, foreground="#93c5fd")

        footer = ttk.Frame(parent, style="Panel.TFrame")
        footer.pack(fill="x", padx=14, pady=(0, 14))
        self.start_button = ttk.Button(footer, text="Mulai Instalasi", style="Accent.TButton", command=self._start)
        self.start_button.pack(side="left")
        self.retry_button = ttk.Button(footer, text="Retry Gagal", command=self._retry_failed, state="disabled")
        self.retry_button.pack(side="left", padx=(8, 0))
        self.stop_button = ttk.Button(footer, text="Berhenti Aman", style="Danger.TButton", command=self._cancel, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.uninstall_selected_button = ttk.Button(
            footer,
            text="Uninstall Domain",
            style="Danger.TButton",
            command=self._uninstall_selected,
        )
        self.uninstall_selected_button.pack(side="left", padx=(8, 0))
        self.uninstall_global_button = ttk.Button(
            footer,
            text="Uninstall Global",
            style="Danger.TButton",
            command=self._uninstall_global,
        )
        self.uninstall_global_button.pack(side="left", padx=(8, 0))
        self.export_button = ttk.Button(footer, text="Ekspor Laporan", command=self._export_report, state="disabled")
        self.export_button.pack(side="right")
        self.count_label = ttk.Label(footer, text="0 domain", style="Muted.TLabel")
        self.count_label.pack(side="right", padx=12)

    def _update_auth_fields(self) -> None:
        # Kredensial lain tetap dapat diisi sebagai fallback. Metode yang dipilih hanya
        # menentukan prioritas percobaan, bukan mematikan opsi lain.
        self.password_entry.configure(state="normal")
        self.key_entry.configure(state="normal")
        self.key_button.configure(state="normal")
        self.passphrase_entry.configure(state="normal")

    def _choose_key(self) -> None:
        path = filedialog.askopenfilename(
            title="Pilih private key",
            filetypes=(("Private key", "*.pem *.key *.ppk"), ("Semua file", "*.*")),
        )
        if path:
            self.key_var.set(path)
            if self.auth_var.get() != "Otomatis":
                if Path(path).suffix.lower() == ".ppk":
                    self.auth_var.set("PPK")
                else:
                    self.auth_var.set("OpenSSH Key")
            self._update_auth_fields()

    def _server_config(self) -> ServerConfig:
        methods = {
            "Otomatis": AuthMethod.AUTO,
            "Password": AuthMethod.PASSWORD,
            "OpenSSH Key": AuthMethod.OPENSSH_KEY,
            "PPK": AuthMethod.PPK,
            "SSH Agent/Pageant": AuthMethod.SSH_AGENT,
        }
        config = ServerConfig(
            host=self.host_var.get().strip(),
            port=int(self.port_var.get()),
            username=self.user_var.get().strip(),
            auth_method=methods[self.auth_var.get()],
            password=self.password_var.get(),
            key_path=self.key_var.get().strip(),
            key_passphrase=self.passphrase_var.get(),
            sudo_password=self.sudo_var.get(),
            concurrency=int(self.concurrent_var.get()),
            prepare_stack=self.prepare_var.get(),
            install_cleanup=True,
        )
        validate_server(config)
        return config

    def _import_csv(self) -> None:
        if self._busy:
            return
        path = filedialog.askopenfilename(title="Pilih CSV domain", filetypes=(("CSV", "*.csv"),))
        if not path:
            return
        try:
            imported = read_sites_csv(path)
            self._merge_sites(imported)
        except Exception as exc:
            messagebox.showerror("Impor gagal", str(exc), parent=self)

    def _bulk_add(self) -> None:
        if self._busy:
            return
        dialog = BulkInputDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            self._merge_sites(dialog.result)

    def _merge_sites(self, new_sites: list[SiteSpec]) -> None:
        combined = {site.domain: site for site in self.sites}
        for site in new_sites:
            combined[site.domain] = site
        self.sites = validate_sites(list(combined.values()))
        self._refresh_tree()

    def _remove_selected(self) -> None:
        if self._busy:
            return
        selected = set(self.tree.selection())
        if not selected:
            return
        self.sites = [site for site in self.sites if site.domain not in selected]
        self.results = [result for result in self.results if result.domain not in selected]
        self._refresh_tree()

    def _refresh_tree(self) -> None:
        result_map = {result.domain: result for result in self.results}
        for item in self.tree.get_children():
            self.tree.delete(item)
        for site in self.sites:
            result = result_map.get(site.domain)
            status = result.status if result else JobStatus.PENDING
            message = result.message if result else "Menunggu"
            self.tree.insert(
                "",
                "end",
                iid=site.domain,
                values=(
                    site.domain,
                    site.title,
                    site.admin_user,
                    site.locale,
                    "Ya" if site.enable_ssl else "Tidak",
                    status.value,
                    message,
                ),
                tags=(status.value,),
            )
        self.count_label.configure(text=f"{len(self.sites)} domain")

    def _log(self, message: str) -> None:
        self.events.put(("log", message))

    def _status(self, domain: str, status: JobStatus, message: str) -> None:
        self.events.put(("status", (domain, status, message)))

    def _set_busy(self, busy: bool, *, cancellable: bool = True) -> None:
        self._busy = busy
        self.start_button.configure(state="disabled" if busy else "normal")
        self.test_button.configure(state="disabled" if busy else "normal")
        self.import_button.configure(state="disabled" if busy else "normal")
        self.bulk_add_button.configure(state="disabled" if busy else "normal")
        self.remove_list_button.configure(state="disabled" if busy else "normal")
        self.uninstall_selected_button.configure(state="disabled" if busy else "normal")
        self.uninstall_global_button.configure(state="disabled" if busy else "normal")
        self.retry_button.configure(
            state="normal" if not busy and any(result.status is JobStatus.FAILED for result in self.results) else "disabled"
        )
        self.export_button.configure(state="normal" if not busy and self.results else "disabled")
        self.stop_button.configure(state="normal" if busy and cancellable else "disabled")
        self.header_status.configure(text="Sedang bekerja…" if busy else "Siap")

    def _test_connection(self) -> None:
        if self._busy:
            return
        try:
            config = self._server_config()
        except Exception as exc:
            messagebox.showerror("Koneksi", str(exc), parent=self)
            return
        installer = BulkInstaller(config, log=self._log)
        self.installer = installer
        self._set_busy(True, cancellable=False)

        def task() -> None:
            try:
                result = installer.test_connection()
                self.events.put(("message", ("Koneksi berhasil", str(result["output"]))))
            except Exception as exc:
                self.events.put(("error", ("Koneksi gagal", str(exc))))
            finally:
                self.events.put(("busy", False))

        self.worker = threading.Thread(target=task, daemon=True)
        self.worker.start()

    def _start(self, selected: list[SiteSpec] | None = None) -> None:
        if self._busy:
            return
        try:
            config = self._server_config()
            targets = validate_sites(selected or self.sites)
        except Exception as exc:
            messagebox.showerror("Belum dapat dimulai", str(exc), parent=self)
            return
        if not messagebox.askyesno(
            "Konfirmasi",
            f"Pasang {len(targets)} WordPress pada {config.host}?\n\n"
            "Gunakan VPS Ubuntu 24.04 baru dan buat snapshot terlebih dahulu.",
            parent=self,
        ):
            return
        self._set_busy(True)
        self.results = [result for result in self.results if result.domain not in {site.domain for site in targets}]
        self._refresh_tree()
        installer = BulkInstaller(config, log=self._log, status=self._status)
        self.installer = installer

        def task() -> None:
            try:
                results = installer.install(targets)
                self.events.put(("complete", results))
            except Exception as exc:
                self.events.put(("error", ("Instalasi berhenti", str(exc))))
            finally:
                self.events.put(("busy", False))

        self.worker = threading.Thread(target=task, daemon=True)
        self.worker.start()

    def _retry_failed(self) -> None:
        if self._busy:
            return
        failed = {result.domain for result in self.results if result.status is JobStatus.FAILED}
        targets = [site for site in self.sites if site.domain in failed]
        if targets:
            self._start(targets)

    def _uninstall_selected(self) -> None:
        if self._busy:
            return
        selected = list(self.tree.selection())
        if selected:
            domains = [validate_domain(value) for value in selected]
        else:
            raw = simpledialog.askstring(
                "Uninstall Domain",
                "Masukkan satu atau beberapa domain dipisahkan koma:\n"
                "contoh: domain1.com, domain2.com",
                parent=self,
            )
            if not raw:
                return
            try:
                domains = [
                    validate_domain(value)
                    for value in raw.replace(",", "\n").splitlines()
                    if value.strip()
                ]
            except Exception as exc:
                messagebox.showerror("Domain tidak valid", str(exc), parent=self)
                return
        domains = list(dict.fromkeys(domains))
        preview = "\n".join(f"• {domain}" for domain in domains[:10])
        if len(domains) > 10:
            preview += f"\n• dan {len(domains) - 10} domain lainnya"
        if not messagebox.askyesno(
            "Konfirmasi uninstall domain",
            f"Hapus permanen {len(domains)} domain dari VPS?\n\n{preview}\n\n"
            "WordPress, database, user Linux, cache, log, vhost, dan sertifikat "
            "domain tersebut akan dihapus. Domain lain tidak disentuh.",
            icon="warning",
            parent=self,
        ):
            return
        self._run_uninstall(domains, global_mode=False)

    def _uninstall_global(self) -> None:
        if self._busy:
            return
        confirmation = simpledialog.askstring(
            "Uninstall Global",
            "Ini akan menghapus SEMUA website yang dikelola BagoesWP beserta database, "
            "user, cache, log, sertifikat, dan konfigurasi manajernya.\n\n"
            "Paket OpenLiteSpeed, MariaDB, dan Redis tetap dipertahankan untuk keamanan.\n\n"
            "Ketik HAPUS SEMUA untuk melanjutkan:",
            parent=self,
        )
        if confirmation is None:
            return
        if confirmation.strip() != "HAPUS SEMUA":
            messagebox.showwarning(
                "Uninstall dibatalkan",
                "Teks konfirmasi tidak cocok. Tidak ada data yang dihapus.",
                parent=self,
            )
            return
        self._run_uninstall([], global_mode=True)

    def _run_uninstall(self, domains: list[str], *, global_mode: bool) -> None:
        if self._busy:
            return
        try:
            config = self._server_config()
        except Exception as exc:
            messagebox.showerror("Uninstall belum dapat dimulai", str(exc), parent=self)
            return
        self._set_busy(True)
        installer = BulkInstaller(config, log=self._log, status=self._status)
        self.installer = installer

        def task() -> None:
            try:
                result = installer.uninstall(domains, global_mode=global_mode)
                self.events.put(("uninstall_complete", (result, global_mode)))
            except Exception as exc:
                self.events.put(("error", ("Uninstall berhenti", str(exc))))
            finally:
                self.events.put(("busy", False))

        self.worker = threading.Thread(target=task, daemon=True)
        self.worker.start()

    def _cancel(self) -> None:
        if self.installer:
            self.installer.cancel()

    def _export_report(self) -> None:
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            title="Simpan laporan",
            defaultextension=".json",
            filetypes=(("JSON", "*.json"),),
            initialfile="bagoeswp-install-report.json",
        )
        if not path:
            return
        data = {
            "version": __version__,
            "summary": summarize_results(self.results),
            "results": [
                {
                    "domain": result.domain,
                    "status": result.status.value,
                    "stage": result.stage,
                    "message": result.message,
                    "checks": result.checks,
                    "remote_report_path": result.report_path,
                }
                for result in self.results
            ],
        }
        Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        messagebox.showinfo("Laporan", "Laporan berhasil disimpan.", parent=self)

    def _drain_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self.log_text.configure(state="normal")
                    self.log_text.insert("end", str(payload) + "\n")
                    self.log_text.see("end")
                    self.log_text.configure(state="disabled")
                elif kind == "status":
                    domain, status, message = payload  # type: ignore[misc]
                    if self.tree.exists(domain):
                        values = list(self.tree.item(domain, "values"))
                        values[5] = status.value
                        values[6] = message
                        self.tree.item(domain, values=values, tags=(status.value,))
                elif kind == "busy":
                    self._set_busy(bool(payload))
                elif kind == "message":
                    title, message = payload  # type: ignore[misc]
                    messagebox.showinfo(title, message, parent=self)
                elif kind == "error":
                    title, message = payload  # type: ignore[misc]
                    messagebox.showerror(title, message, parent=self)
                elif kind == "complete":
                    incoming: list[JobResult] = payload  # type: ignore[assignment]
                    incoming_domains = {result.domain for result in incoming}
                    self.results = [result for result in self.results if result.domain not in incoming_domains] + incoming
                    self._refresh_tree()
                    summary = summarize_results(self.results)
                    self.retry_button.configure(
                        state="normal" if not self._busy and summary[JobStatus.FAILED.value] else "disabled"
                    )
                    self.export_button.configure(state="normal" if not self._busy else "disabled")
                    messagebox.showinfo(
                        "Proses selesai",
                        f"Optimal: {summary[JobStatus.OPTIMAL.value]}\n"
                        f"Verified: {summary[JobStatus.VERIFIED.value]}\n"
                        f"Terpasang: {summary[JobStatus.INSTALLED.value]}\n"
                        f"SSL pending: {summary[JobStatus.INSTALLED_PENDING_SSL.value]}\n"
                        f"Gagal: {summary[JobStatus.FAILED.value]}",
                        parent=self,
                    )
                elif kind == "uninstall_complete":
                    result, global_mode = payload  # type: ignore[misc]
                    removed = set(map(str, result.get("removed", []) or []))
                    not_found = list(map(str, result.get("not_found", []) or []))
                    failed = dict(result.get("failed", {}) or {})
                    warnings = list(map(str, result.get("warnings", []) or []))
                    if global_mode and not failed:
                        self.sites = []
                        self.results = []
                    else:
                        self.sites = [site for site in self.sites if site.domain not in removed]
                        self.results = [
                            item for item in self.results if item.domain not in removed | set(failed)
                        ]
                        for domain, detail in failed.items():
                            if any(site.domain == domain for site in self.sites):
                                self.results.append(
                                    JobResult(
                                        domain,
                                        JobStatus.FAILED,
                                        "uninstall",
                                        str(detail),
                                    )
                                )
                    self._refresh_tree()
                    lines = [f"Berhasil dihapus: {len(removed)}"]
                    if not_found:
                        lines.append("Tidak ditemukan: " + ", ".join(not_found))
                    if failed:
                        lines.append("Gagal: " + ", ".join(failed))
                    if warnings:
                        lines.append("Peringatan: " + "; ".join(warnings))
                    if global_mode and not failed:
                        lines.append("Paket OLS, MariaDB, dan Redis tetap terpasang.")
                    title = "Uninstall selesai" if not failed and not warnings else "Uninstall sebagian"
                    messagebox.showinfo(title, "\n".join(lines), parent=self)
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _on_close(self) -> None:
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno(
                "Masih berjalan",
                "Job aktif akan tetap berjalan di VPS sampai tahap amannya selesai. Tutup aplikasi?",
                parent=self,
            ):
                return
            if self.installer:
                self.installer.cancel()
        self.destroy()


def main() -> None:
    log_path = app_log_path()
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"[{datetime.now().isoformat(timespec='seconds')}] BagoesWP v{__version__} mulai\n")
    try:
        app = BagoesWPApp()
        app.mainloop()
    except Exception as exc:
        path = write_app_exception(type(exc), exc, exc.__traceback__)
        try:
            messagebox.showerror("BagoesWP gagal dibuka", f"Detail error disimpan di:\n{path}")
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
