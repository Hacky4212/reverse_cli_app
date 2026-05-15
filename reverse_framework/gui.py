from __future__ import annotations

import os
import queue
import threading
import traceback
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import filedialog, scrolledtext, ttk
except Exception as exc:  # pragma: no cover - import guard for headless builds.
    tk = None  # type: ignore[assignment]
    tkfont = None  # type: ignore[assignment]
    filedialog = None  # type: ignore[assignment]
    scrolledtext = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    _TK_IMPORT_ERROR = exc
else:
    _TK_IMPORT_ERROR = None

from reverse_framework.api import (
    analyze_and_write_reports,
    analyze_code_text_and_write_reports,
    analyze_execution_evidence_and_write_reports,
    analyze_process_memory_and_write_reports,
    available_analyzers,
    stream_live_kernel_events,
)
from reverse_framework.core.config import TriageConfig, load_config
from reverse_framework.core.process_lookup import resolve_process_candidate
from reverse_framework.reporting import ReportFormat, summarize_finding


@dataclass(slots=True)
class GuiTask:
    mode: str
    config: TriageConfig
    analyzers: list[str] | None
    out_dir: Path
    report_format: ReportFormat
    target_label: str = ""
    target: Path | None = None
    code_text: str = ""
    code_name: str = "analysis-input.txt"
    evidence_text: str = ""
    evidence_name: str = "execution-evidence"
    static_code: str | None = None
    pid: int | None = None
    process_name: str = ""
    window_title: str = ""
    live_duration: int | None = None
    live_include_processes: bool = True
    live_include_threads: bool = True
    live_include_images: bool = True
    address: str | None = None
    size: int = 64


class ReverseToolsApp:
    def __init__(self, root: "tk.Tk") -> None:
        self.root = root
        self.root.title("reverse-tools - static + dynamic triage")
        self.root.geometry("1320x920")
        self.root.minsize(1100, 780)

        self.available_analyzers = available_analyzers()
        self.message_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.worker_thread: threading.Thread | None = None
        self.live_stop_event: threading.Event | None = None
        self.active_task_mode: str | None = None

        fixed_font = tkfont.Font(family="Consolas", size=10) if tkfont is not None else None
        self.fixed_font = fixed_font
        self.colors = {
            "background": "#edf2f7",
            "surface": "#ffffff",
            "surface_alt": "#f8fafc",
            "border": "#dbe3ef",
            "text": "#0f172a",
            "muted": "#64748b",
            "primary": "#2563eb",
            "primary_dark": "#1d4ed8",
            "danger": "#dc2626",
            "danger_dark": "#b91c1c",
            "header": "#0f172a",
            "header_soft": "#1e293b",
            "log_bg": "#0b1120",
            "log_text": "#dbeafe",
        }

        self.config_path_var = tk.StringVar(value="")
        self.out_dir_var = tk.StringVar(value="reports")
        self.format_var = tk.StringVar(value="all")
        self.min_string_var = tk.StringVar(value="")
        self.max_strings_var = tk.StringVar(value="")
        self.native_probe_var = tk.StringVar(value="")
        self.perf_scan_var = tk.StringVar(value="")
        self.process_memory_var = tk.StringVar(value="")
        self.target_var = tk.StringVar(value="")
        self.code_name_var = tk.StringVar(value="analysis-input.txt")
        self.evidence_name_var = tk.StringVar(value="execution-evidence")
        self.pid_var = tk.StringVar(value="")
        self.process_name_var = tk.StringVar(value="")
        self.window_title_var = tk.StringVar(value="")
        self.live_pid_var = tk.StringVar(value="")
        self.live_process_name_var = tk.StringVar(value="")
        self.live_window_title_var = tk.StringVar(value="")
        self.live_duration_var = tk.StringVar(value="30")
        self.live_include_processes_var = tk.BooleanVar(value=True)
        self.live_include_threads_var = tk.BooleanVar(value=True)
        self.live_include_images_var = tk.BooleanVar(value=True)
        self.address_var = tk.StringVar(value="")
        self.size_var = tk.StringVar(value="64")
        self.status_var = tk.StringVar(value="Ready")
        self.notice_var = tk.StringVar(value="")
        self.live_target_status_var = tk.StringVar(value="Target: all processes")
        self.memory_target_status_var = tk.StringVar(value="Target: not resolved")
        self.mode_var = tk.StringVar(value="file")
        self.mode_buttons: dict[str, tk.Button] = {}
        self.mode_pages: dict[str, tk.Widget] = {}
        self.mode_canvases: dict[str, tk.Canvas] = {}
        self.analyzer_vars: dict[str, tk.BooleanVar] = {}

        self._configure_style()
        self._build_ui()
        self._poll_messages()

    def _configure_style(self) -> None:
        self.root.configure(bg=self.colors["background"])

        style = ttk.Style(self.root)
        try:
            if "clam" in style.theme_names():
                style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", font=("Segoe UI", 10), foreground=self.colors["text"])
        style.configure("App.TFrame", background=self.colors["background"])
        style.configure("Card.TFrame", background=self.colors["surface"])
        style.configure("Action.TFrame", background=self.colors["surface"])
        style.configure("Header.TFrame", background=self.colors["header"])
        style.configure("Tab.TFrame", background=self.colors["surface"])
        style.configure("TLabel", background=self.colors["background"], foreground=self.colors["text"])
        style.configure("Card.TLabel", background=self.colors["surface"], foreground=self.colors["text"])
        style.configure("Action.TLabel", background=self.colors["surface"], foreground=self.colors["text"])
        style.configure(
            "HeroTitle.TLabel",
            background=self.colors["header"],
            foreground="#f8fafc",
            font=("Segoe UI Semibold", 22),
        )
        style.configure(
            "HeroSub.TLabel",
            background=self.colors["header"],
            foreground="#cbd5e1",
            font=("Segoe UI", 10),
        )
        style.configure("Badge.TLabel", background=self.colors["header_soft"], foreground="#e0f2fe", padding=(8, 4))
        style.configure(
            "Section.TLabel",
            background=self.colors["surface"],
            foreground=self.colors["text"],
            font=("Segoe UI Semibold", 12),
        )
        style.configure(
            "Hint.TLabel",
            background=self.colors["surface"],
            foreground=self.colors["muted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "Status.TLabel",
            background=self.colors["surface"],
            foreground=self.colors["primary"],
            font=("Segoe UI Semibold", 10),
        )
        style.configure(
            "Notice.TLabel",
            background="#eff6ff",
            foreground=self.colors["primary"],
            padding=(10, 7),
            font=("Segoe UI", 9),
        )
        style.configure(
            "Error.TLabel",
            background="#fef2f2",
            foreground=self.colors["danger"],
            padding=(10, 7),
            font=("Segoe UI", 9),
        )
        style.configure(
            "Field.TLabel",
            background=self.colors["surface"],
            foreground=self.colors["text"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "Card.TLabelframe",
            background=self.colors["surface"],
            bordercolor=self.colors["border"],
            relief="solid",
        )
        style.configure(
            "Card.TLabelframe.Label",
            background=self.colors["surface"],
            foreground=self.colors["text"],
            font=("Segoe UI Semibold", 11),
        )
        style.configure(
            "TEntry",
            fieldbackground="#ffffff",
            bordercolor=self.colors["border"],
            lightcolor=self.colors["border"],
            padding=5,
        )
        style.configure("TCombobox", fieldbackground="#ffffff", bordercolor=self.colors["border"], padding=5)
        style.configure("TCheckbutton", background=self.colors["surface"], foreground=self.colors["text"])
        style.configure("TButton", padding=(11, 6), borderwidth=0)
        style.configure(
            "Primary.TButton",
            background=self.colors["primary"],
            foreground="#ffffff",
            padding=(15, 7),
            borderwidth=0,
        )
        style.map(
            "Primary.TButton",
            background=[("active", self.colors["primary_dark"]), ("disabled", "#94a3b8")],
            foreground=[("disabled", "#e2e8f0")],
        )
        style.configure(
            "Danger.TButton",
            background=self.colors["danger"],
            foreground="#ffffff",
            padding=(13, 7),
            borderwidth=0,
        )
        style.map("Danger.TButton", background=[("active", self.colors["danger_dark"]), ("disabled", "#fca5a5")])

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        main = ttk.Frame(self.root, padding=14, style="App.TFrame")
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=1)

        self._build_header(main)

        content = ttk.Frame(main, style="App.TFrame")
        content.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        content.columnconfigure(0, weight=0, minsize=360)
        content.columnconfigure(1, weight=1)
        content.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(content, style="App.TFrame")
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        sidebar.columnconfigure(0, weight=1)
        sidebar.rowconfigure(1, weight=1)

        options_frame = ttk.LabelFrame(sidebar, text="Global Settings", padding=12, style="Card.TLabelframe")
        options_frame.grid(row=0, column=0, sticky="ew")
        options_frame.columnconfigure(1, weight=1)

        self._add_path_row(options_frame, 0, "Config JSON (optional)", self.config_path_var, browse="config")
        self._add_path_row(options_frame, 1, "Output", self.out_dir_var, browse="dir")
        self._add_format_row(options_frame, 2)
        self._add_simple_row(options_frame, 3, "Min string", self.min_string_var)
        self._add_simple_row(options_frame, 4, "Max strings", self.max_strings_var)
        self._add_path_row(options_frame, 5, "Native probe", self.native_probe_var, browse="file")
        self._add_path_row(options_frame, 6, "C++ perf scan", self.perf_scan_var, browse="file")
        self._add_path_row(options_frame, 7, "Process memory", self.process_memory_var, browse="file")

        ttk.Label(
            options_frame,
            text="First use: leave Config blank. Use File for an EXE sample; use Live/Memory for dynamic input.",
            style="Hint.TLabel",
            wraplength=315,
        ).grid(row=8, column=0, columnspan=3, sticky="w", pady=(4, 0))

        analyzers_frame = ttk.LabelFrame(sidebar, text="Analyzer Set", padding=12, style="Card.TLabelframe")
        analyzers_frame.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        analyzers_frame.columnconfigure(0, weight=1)
        analyzers_frame.rowconfigure(0, weight=1)

        list_frame = ttk.Frame(analyzers_frame, style="Card.TFrame")
        list_frame.grid(row=0, column=0, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        analyzer_canvas = tk.Canvas(list_frame, bg=self.colors["surface"], highlightthickness=0, borderwidth=0, height=260)
        analyzer_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=analyzer_canvas.yview)
        analyzer_canvas.configure(yscrollcommand=analyzer_scrollbar.set)
        analyzer_canvas.grid(row=0, column=0, sticky="nsew")
        analyzer_scrollbar.grid(row=0, column=1, sticky="ns")

        analyzer_content = ttk.Frame(analyzer_canvas, style="Card.TFrame")
        analyzer_window = analyzer_canvas.create_window((0, 0), window=analyzer_content, anchor="nw")
        analyzer_content.columnconfigure(0, weight=1)
        analyzer_content.bind(
            "<Configure>",
            lambda _: analyzer_canvas.configure(scrollregion=analyzer_canvas.bbox("all")),
        )
        analyzer_canvas.bind("<Configure>", lambda event: analyzer_canvas.itemconfigure(analyzer_window, width=event.width))

        for row, name in enumerate(self.available_analyzers):
            variable = tk.BooleanVar(value=True)
            self.analyzer_vars[name] = variable
            ttk.Checkbutton(analyzer_content, text=name, variable=variable).grid(row=row, column=0, sticky="w", pady=1)
        self._bind_mousewheel_recursive(analyzer_canvas, analyzer_canvas)

        analyzer_buttons = ttk.Frame(list_frame, style="Card.TFrame")
        analyzer_buttons.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        analyzer_buttons.columnconfigure(2, weight=1)
        ttk.Button(analyzer_buttons, text="All", command=self._select_all_analyzers).grid(row=0, column=0)
        ttk.Button(analyzer_buttons, text="Clear", command=self._clear_analyzers).grid(row=0, column=1, padx=(6, 0))
        ttk.Label(
            list_frame,
            text="None checked uses the mode default.",
            style="Hint.TLabel",
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))

        workbench = ttk.Frame(content, style="App.TFrame")
        workbench.grid(row=0, column=1, sticky="nsew")
        workbench.columnconfigure(0, weight=1)
        workbench.rowconfigure(0, weight=4)
        workbench.rowconfigure(2, weight=3)

        tabs_card = ttk.Frame(workbench, padding=10, style="Card.TFrame")
        tabs_card.grid(row=0, column=0, sticky="nsew")
        tabs_card.columnconfigure(0, weight=1)
        tabs_card.rowconfigure(2, weight=1)

        ttk.Label(tabs_card, text="Workspace", style="Section.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))

        mode_bar = ttk.Frame(tabs_card, style="Card.TFrame")
        mode_bar.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        mode_bar.columnconfigure(5, weight=1)
        for index, (mode, label) in enumerate(
            (
                ("file", "Static EXE"),
                ("code", "Code Text"),
                ("evidence", "Trace Evidence"),
                ("live", "Live Monitor"),
                ("memory", "Memory Read"),
            )
        ):
            self._add_mode_button(mode_bar, index, mode, label)

        page_host = ttk.Frame(tabs_card, style="Card.TFrame")
        page_host.grid(row=2, column=0, sticky="nsew")
        page_host.columnconfigure(0, weight=1)
        page_host.rowconfigure(0, weight=1)

        file_tab = self._create_scrollable_page(page_host, "file")
        code_tab = self._create_scrollable_page(page_host, "code")
        evidence_tab = self._create_scrollable_page(page_host, "evidence")
        live_tab = self._create_scrollable_page(page_host, "live")
        memory_tab = self._create_scrollable_page(page_host, "memory")

        self._build_file_tab(file_tab)
        self._build_code_tab(code_tab)
        self._build_evidence_tab(evidence_tab)
        self._build_live_tab(live_tab)
        self._build_memory_tab(memory_tab)
        for mode, page in self.mode_pages.items():
            self._bind_mousewheel_recursive(page, self.mode_canvases[mode])
        self._select_mode("file")

        controls = ttk.Frame(workbench, padding=(12, 10), style="Action.TFrame")
        controls.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        controls.columnconfigure(0, weight=1)

        status_frame = ttk.Frame(controls, style="Action.TFrame")
        status_frame.grid(row=0, column=0, sticky="w")
        ttk.Label(status_frame, text="Status", style="Action.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(status_frame, textvariable=self.status_var, style="Status.TLabel").grid(row=0, column=1, sticky="w", padx=(8, 0))

        button_row = ttk.Frame(controls, style="Action.TFrame")
        button_row.grid(row=0, column=1, sticky="e")
        self.run_button = ttk.Button(button_row, text="Run Analysis", command=self.run_analysis, style="Primary.TButton")
        self.run_button.grid(row=0, column=0)
        ttk.Button(button_row, text="Open Output", command=self.open_output_dir).grid(row=0, column=1, padx=(6, 0))
        ttk.Button(button_row, text="Clear Log", command=self.clear_log).grid(row=0, column=2, padx=(6, 0))
        self.stop_button = ttk.Button(button_row, text="Stop", command=self.stop_live_monitor, state="disabled", style="Danger.TButton")
        self.stop_button.grid(row=0, column=3, padx=(6, 0))

        self.notice_label = ttk.Label(controls, textvariable=self.notice_var, style="Notice.TLabel")
        self.notice_label.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        self.notice_label.grid_remove()

        log_frame = ttk.LabelFrame(workbench, text="Console Log", padding=10, style="Card.TLabelframe")
        log_frame.grid(row=2, column=0, sticky="nsew", pady=(12, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_widget = scrolledtext.ScrolledText(
            log_frame,
            height=12,
            wrap="word",
            font=self.fixed_font,
            state="disabled",
        )
        self._style_text_widget(self.log_widget, dark=True)
        self._configure_log_tags()
        self.log_widget.grid(row=0, column=0, sticky="nsew")

    def _build_header(self, parent: "ttk.Frame") -> None:
        header = ttk.Frame(parent, padding=(18, 12), style="Header.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text="reverse-tools", style="HeroTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="Python orchestrates CLI/GUI; C handles low-level access; C++ is reserved for hot paths.",
            style="HeroSub.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        badges = ttk.Frame(header, style="Header.TFrame")
        badges.grid(row=0, column=1, rowspan=2, sticky="e")
        for index, label in enumerate(("Static EXE", "PID / Name / Window", "Dynamic Monitor")):
            ttk.Label(badges, text=label, style="Badge.TLabel").grid(row=0, column=index, padx=(8 if index else 0, 0))

    def _add_mode_button(self, parent: "ttk.Frame", column: int, mode: str, label: str) -> None:
        button = tk.Button(
            parent,
            text=label,
            command=lambda: self._select_mode(mode),
            relief="flat",
            borderwidth=0,
            padx=12,
            pady=7,
            font=("Segoe UI Semibold", 9),
            cursor="hand2",
        )
        button.grid(row=0, column=column, sticky="w", padx=(0, 8))
        self.mode_buttons[mode] = button

    def _select_mode(self, mode: str) -> None:
        self.mode_var.set(mode)
        page = self.mode_pages.get(mode)
        if page is not None:
            page.tkraise()

        for button_mode, button in self.mode_buttons.items():
            if button_mode == mode:
                button.configure(bg=self.colors["primary"], fg="#ffffff", activebackground=self.colors["primary_dark"])
            else:
                button.configure(bg=self.colors["surface_alt"], fg=self.colors["text"], activebackground="#dbeafe")

    def _create_scrollable_page(self, parent: "ttk.Frame", mode: str) -> "ttk.Frame":
        outer = ttk.Frame(parent, style="Card.TFrame")
        outer.grid(row=0, column=0, sticky="nsew")
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)

        canvas = tk.Canvas(outer, bg=self.colors["surface"], highlightthickness=0, borderwidth=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        content = ttk.Frame(canvas, padding=10, style="Tab.TFrame")
        window_id = canvas.create_window((0, 0), window=content, anchor="nw")
        content.columnconfigure(0, weight=1)

        def update_scroll_region(_: tk.Event) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def update_content_width(event: tk.Event) -> None:
            canvas.itemconfigure(window_id, width=event.width)

        content.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", update_content_width)
        self.mode_pages[mode] = outer
        self.mode_canvases[mode] = canvas
        return content

    def _bind_mousewheel_recursive(self, widget: "tk.Widget", canvas: "tk.Canvas") -> None:
        def scroll(event: tk.Event) -> None:
            delta = getattr(event, "delta", 0)
            if delta:
                canvas.yview_scroll(int(-delta / 120), "units")

        widget.bind("<MouseWheel>", scroll, add="+")
        widget.bind("<Button-4>", lambda _: canvas.yview_scroll(-1, "units"), add="+")
        widget.bind("<Button-5>", lambda _: canvas.yview_scroll(1, "units"), add="+")
        for child in widget.winfo_children():
            self._bind_mousewheel_recursive(child, canvas)

    def _style_text_widget(self, widget: "scrolledtext.ScrolledText", *, dark: bool = False) -> None:
        if dark:
            widget.configure(
                bg=self.colors["log_bg"],
                fg=self.colors["log_text"],
                insertbackground="#f8fafc",
                selectbackground=self.colors["primary"],
                relief="flat",
                borderwidth=0,
                padx=10,
                pady=8,
            )
            return

        widget.configure(
            bg=self.colors["surface_alt"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            selectbackground="#bfdbfe",
            relief="flat",
            borderwidth=0,
            padx=8,
            pady=6,
        )

    def _configure_log_tags(self) -> None:
        self.log_widget.tag_configure("error", foreground="#fca5a5")
        self.log_widget.tag_configure("live", foreground="#93c5fd")
        self.log_widget.tag_configure("success", foreground="#86efac")
        self.log_widget.tag_configure("meta", foreground="#cbd5e1")

    def _add_section_header(self, parent: "ttk.Frame", row: int, title: str, hint: str, *, columnspan: int = 3) -> None:
        ttk.Label(parent, text=title, style="Section.TLabel").grid(row=row, column=0, columnspan=columnspan, sticky="w")
        ttk.Label(parent, text=hint, style="Hint.TLabel", wraplength=720).grid(
            row=row + 1,
            column=0,
            columnspan=columnspan,
            sticky="w",
            pady=(2, 12),
        )

    def _build_file_tab(self, parent: "ttk.Frame") -> None:
        parent.columnconfigure(1, weight=1)
        self._add_section_header(
            parent,
            0,
            "Static EXE triage",
            "Pick the executable, DLL, driver, or packed sample. Reports are written to the output folder.",
        )
        ttk.Label(parent, text="Target file", style="Card.TLabel").grid(row=2, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.target_var).grid(row=2, column=1, sticky="ew")
        ttk.Button(parent, text="Browse", command=lambda: self._pick_file(self.target_var)).grid(row=2, column=2, padx=(6, 0))

    def _build_code_tab(self, parent: "ttk.Frame") -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(4, weight=1)

        self._add_section_header(
            parent,
            0,
            "Code text triage",
            "Paste decompiler output, assembly, IR, or suspicious snippets when you do not have a file sample.",
            columnspan=1,
        )

        header = ttk.Frame(parent, style="Card.TFrame")
        header.grid(row=2, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)
        ttk.Label(header, text="Name", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Entry(header, textvariable=self.code_name_var).grid(row=0, column=1, sticky="ew")

        ttk.Label(parent, text="Code text", style="Card.TLabel").grid(row=3, column=0, sticky="w", pady=(10, 0))
        self.code_text_widget = scrolledtext.ScrolledText(parent, height=12, wrap="word", font=self.fixed_font)
        self._style_text_widget(self.code_text_widget)
        self.code_text_widget.grid(row=4, column=0, sticky="nsew")

    def _build_evidence_tab(self, parent: "ttk.Frame") -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(4, weight=1)
        parent.rowconfigure(6, weight=1)

        self._add_section_header(
            parent,
            0,
            "Dynamic evidence triage",
            "Paste runtime traces, syscall logs, memory notes, or sandbox output and compare it with static code.",
            columnspan=1,
        )

        header = ttk.Frame(parent, style="Card.TFrame")
        header.grid(row=2, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)
        ttk.Label(header, text="Name", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Entry(header, textvariable=self.evidence_name_var).grid(row=0, column=1, sticky="ew")

        ttk.Label(parent, text="Evidence text", style="Card.TLabel").grid(row=3, column=0, sticky="w", pady=(10, 0))
        self.evidence_text_widget = scrolledtext.ScrolledText(parent, height=10, wrap="word", font=self.fixed_font)
        self._style_text_widget(self.evidence_text_widget)
        self.evidence_text_widget.grid(row=4, column=0, sticky="nsew")

        ttk.Label(parent, text="Static code", style="Card.TLabel").grid(row=5, column=0, sticky="w", pady=(10, 0))
        self.static_code_widget = scrolledtext.ScrolledText(parent, height=8, wrap="word", font=self.fixed_font)
        self._style_text_widget(self.static_code_widget)
        self.static_code_widget.grid(row=6, column=0, sticky="nsew")

    def _build_live_tab(self, parent: "ttk.Frame") -> None:
        parent.columnconfigure(0, weight=1)

        self._add_section_header(
            parent,
            0,
            "Live dynamic monitor",
            "Use PID, process name, or window title to focus a running program. Leave target blank to monitor all.",
            columnspan=1,
        )

        target_frame = ttk.LabelFrame(parent, text="Target", padding=12, style="Card.TLabelframe")
        target_frame.grid(row=2, column=0, sticky="ew")
        target_frame.columnconfigure(1, weight=1)
        target_frame.columnconfigure(3, weight=1)

        ttk.Label(target_frame, text="PID", style="Field.TLabel").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(target_frame, textvariable=self.live_pid_var, width=16).grid(row=0, column=1, sticky="ew", padx=(10, 18), pady=4)
        ttk.Label(target_frame, text="Process name", style="Field.TLabel").grid(row=0, column=2, sticky="w", pady=4)
        ttk.Entry(target_frame, textvariable=self.live_process_name_var, width=24).grid(row=0, column=3, sticky="ew", pady=4)
        ttk.Label(target_frame, text="Window title", style="Field.TLabel").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(target_frame, textvariable=self.live_window_title_var).grid(
            row=1,
            column=1,
            columnspan=3,
            sticky="ew",
            padx=(10, 0),
            pady=4,
        )
        ttk.Label(
            target_frame,
            text="Leave blank to watch all live events.",
            style="Hint.TLabel",
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(6, 0))
        ttk.Button(target_frame, text="Resolve Target", command=self.resolve_live_target).grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Label(target_frame, textvariable=self.live_target_status_var, style="Hint.TLabel").grid(
            row=3,
            column=1,
            columnspan=3,
            sticky="w",
            padx=(10, 0),
            pady=(8, 0),
        )

        capture_frame = ttk.LabelFrame(parent, text="Capture", padding=12, style="Card.TLabelframe")
        capture_frame.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        capture_frame.columnconfigure(1, weight=1)

        ttk.Label(capture_frame, text="Duration seconds", style="Field.TLabel").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(capture_frame, textvariable=self.live_duration_var, width=16).grid(row=0, column=1, sticky="w", padx=(10, 0), pady=4)
        checks = ttk.Frame(capture_frame, style="Card.TFrame")
        checks.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Checkbutton(checks, text="Process events", variable=self.live_include_processes_var).grid(row=0, column=0, sticky="w", padx=(0, 18))
        ttk.Checkbutton(checks, text="Thread events", variable=self.live_include_threads_var).grid(row=0, column=1, sticky="w", padx=(0, 18))
        ttk.Checkbutton(checks, text="Module events", variable=self.live_include_images_var).grid(row=0, column=2, sticky="w")

        ttk.Label(
            parent,
            text="Use this tab for dynamic monitoring. The log below shows live events.",
            style="Hint.TLabel",
        ).grid(row=4, column=0, sticky="w", pady=(10, 0))

    def _build_memory_tab(self, parent: "ttk.Frame") -> None:
        parent.columnconfigure(0, weight=1)

        self._add_section_header(
            parent,
            0,
            "Process memory read",
            "Resolve the process by PID, process name, or window title, then read a specific address defensively.",
            columnspan=1,
        )

        target_frame = ttk.LabelFrame(parent, text="Target", padding=12, style="Card.TLabelframe")
        target_frame.grid(row=2, column=0, sticky="ew")
        target_frame.columnconfigure(1, weight=1)
        target_frame.columnconfigure(3, weight=1)

        ttk.Label(target_frame, text="PID", style="Field.TLabel").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(target_frame, textvariable=self.pid_var, width=16).grid(row=0, column=1, sticky="ew", padx=(10, 18), pady=4)
        ttk.Label(target_frame, text="Process name", style="Field.TLabel").grid(row=0, column=2, sticky="w", pady=4)
        ttk.Entry(target_frame, textvariable=self.process_name_var, width=24).grid(row=0, column=3, sticky="ew", pady=4)
        ttk.Label(target_frame, text="Window title", style="Field.TLabel").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(target_frame, textvariable=self.window_title_var).grid(
            row=1,
            column=1,
            columnspan=3,
            sticky="ew",
            padx=(10, 0),
            pady=4,
        )
        ttk.Label(
            target_frame,
            text="PID is optional when process name or window title is available.",
            style="Hint.TLabel",
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(6, 0))
        ttk.Button(target_frame, text="Resolve Target", command=self.resolve_memory_target).grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Label(target_frame, textvariable=self.memory_target_status_var, style="Hint.TLabel").grid(
            row=3,
            column=1,
            columnspan=3,
            sticky="w",
            padx=(10, 0),
            pady=(8, 0),
        )

        read_frame = ttk.LabelFrame(parent, text="Read", padding=12, style="Card.TLabelframe")
        read_frame.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        read_frame.columnconfigure(1, weight=1)
        read_frame.columnconfigure(3, weight=0)

        ttk.Label(read_frame, text="Address", style="Field.TLabel").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(read_frame, textvariable=self.address_var).grid(row=0, column=1, sticky="ew", padx=(10, 18), pady=4)
        ttk.Label(read_frame, text="Size", style="Field.TLabel").grid(row=0, column=2, sticky="w", pady=4)
        ttk.Entry(read_frame, textvariable=self.size_var, width=12).grid(row=0, column=3, sticky="w", padx=(10, 0), pady=4)

    def _add_path_row(self, parent: "ttk.Frame", row: int, label: str, variable: tk.StringVar, browse: str) -> None:
        ttk.Label(parent, text=label, style="Card.TLabel").grid(row=row, column=0, sticky="w", pady=3)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", pady=2)

        if browse == "file":
            command = lambda: self._pick_file(variable)
        elif browse == "config":
            command = lambda: self._pick_config(variable)
        elif browse == "dir":
            command = lambda: self._pick_directory(variable)
        else:
            command = None

        if command is not None:
            ttk.Button(parent, text="Browse", command=command).grid(row=row, column=2, padx=(6, 0), pady=2)

    def _add_simple_row(self, parent: "ttk.Frame", row: int, label: str, variable: tk.StringVar) -> None:
        ttk.Label(parent, text=label, style="Card.TLabel").grid(row=row, column=0, sticky="w", pady=3)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", pady=2)

    def _add_format_row(self, parent: "ttk.Frame", row: int) -> None:
        ttk.Label(parent, text="Format", style="Card.TLabel").grid(row=row, column=0, sticky="w", pady=3)
        format_box = ttk.Combobox(parent, textvariable=self.format_var, values=("all", "json", "markdown"), state="readonly")
        format_box.grid(row=row, column=1, sticky="ew", pady=2)

    def _pick_file(self, variable: tk.StringVar) -> None:
        path = filedialog.askopenfilename(
            title="Select file",
            filetypes=[("Executable and PE files", ("*.exe", "*.dll", "*.sys")), ("All files", "*.*")],
        )
        if path:
            variable.set(path)

    def _pick_config(self, variable: tk.StringVar) -> None:
        path = filedialog.askopenfilename(
            title="Select JSON config",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            variable.set(path)

    def _pick_directory(self, variable: tk.StringVar) -> None:
        path = filedialog.askdirectory(title="Select directory")
        if path:
            variable.set(path)

    def _select_all_analyzers(self) -> None:
        for variable in self.analyzer_vars.values():
            variable.set(True)

    def _clear_analyzers(self) -> None:
        for variable in self.analyzer_vars.values():
            variable.set(False)

    def _select_analyzers(self, names: list[str]) -> None:
        wanted = set(names)
        for name, variable in self.analyzer_vars.items():
            variable.set(name in wanted)

    def _selected_analyzers(self) -> list[str] | None:
        selected = []
        for name in self.available_analyzers:
            variable = self.analyzer_vars.get(name)
            if variable is not None and variable.get():
                selected.append(name)
        if len(selected) == len(self.available_analyzers):
            return None
        if not selected:
            return None
        return selected

    def resolve_live_target(self) -> None:
        try:
            pid, label = self._resolve_process_target(
                self.live_pid_var.get(),
                self.live_process_name_var.get(),
                self.live_window_title_var.get(),
                allow_blank=True,
            )
        except Exception as exc:
            self.live_target_status_var.set("Target: resolve failed")
            self._append_log(f"Error: {exc}")
            self._show_error(str(exc))
            return

        target_text = "all processes" if pid is None else label
        self.live_target_status_var.set(f"Target: {target_text}")
        self._show_notice(f"Resolved live target: {target_text}")

    def resolve_memory_target(self) -> None:
        try:
            _, label = self._resolve_process_target(
                self.pid_var.get(),
                self.process_name_var.get(),
                self.window_title_var.get(),
                allow_blank=False,
            )
        except Exception as exc:
            self.memory_target_status_var.set("Target: resolve failed")
            self._append_log(f"Error: {exc}")
            self._show_error(str(exc))
            return

        self.memory_target_status_var.set(f"Target: {label}")
        self._show_notice(f"Resolved memory target: {label}")

    def run_analysis(self) -> None:
        if self.worker_thread is not None and self.worker_thread.is_alive():
            self._show_error("An analysis is already running.")
            return

        self._clear_notice()
        try:
            task = self._collect_task()
        except Exception as exc:
            self._append_log(f"Error: {exc}")
            self._show_error(str(exc))
            return

        self.active_task_mode = task.mode
        self.live_stop_event = threading.Event() if task.mode == "live" else None
        self._set_busy(True)
        self._append_log(f"Starting {task.mode} analysis...")
        self._append_log(f"Target: {task.target_label or self._describe_target(task)}")
        if task.mode == "live":
            duration_text = "until interrupted" if not task.live_duration else f"{task.live_duration} seconds"
            self._append_log(f"Duration: {duration_text}")
            self._append_log(
                "Filters: "
                f"processes={'on' if task.live_include_processes else 'off'}, "
                f"threads={'on' if task.live_include_threads else 'off'}, "
                f"images={'on' if task.live_include_images else 'off'}"
            )
        else:
            self._append_log(f"Output: {task.out_dir}")
            self._append_log(f"Format: {task.report_format}")

        if task.mode == "live":
            self.worker_thread = threading.Thread(
                target=self._run_live_task,
                args=(task, self.live_stop_event),
                daemon=True,
            )
        else:
            self.worker_thread = threading.Thread(target=self._run_task, args=(task,), daemon=True)
        self.worker_thread.start()

    def _collect_task(self) -> GuiTask:
        config = self._load_config()
        analyzers = self._selected_analyzers()
        out_dir = Path(self.out_dir_var.get().strip() or "reports").expanduser()
        report_format = self._validate_report_format(self.format_var.get().strip() or "all")

        mode = self._active_mode()
        if mode == "file":
            target_text = self.target_var.get().strip()
            if not target_text:
                raise ValueError("Target is required.")
            target = Path(target_text).expanduser()
            if not target.exists():
                raise ValueError(f"Target not found: {target}")
            if not target.is_file():
                raise ValueError(f"Target is not a file: {target}")
            return GuiTask(
                mode=mode,
                config=config,
                analyzers=analyzers,
                out_dir=out_dir,
                report_format=report_format,
                target_label=str(target),
                target=target,
            )

        if mode == "code":
            return GuiTask(
                mode=mode,
                config=config,
                analyzers=analyzers,
                out_dir=out_dir,
                report_format=report_format,
                target_label=self.code_name_var.get().strip() or "analysis-input.txt",
                code_text=self.code_text_widget.get("1.0", tk.END),
                code_name=self.code_name_var.get().strip() or "analysis-input.txt",
            )

        if mode == "evidence":
            static_code = self.static_code_widget.get("1.0", tk.END)
            return GuiTask(
                mode=mode,
                config=config,
                analyzers=analyzers,
                out_dir=out_dir,
                report_format=report_format,
                target_label=self.evidence_name_var.get().strip() or "execution-evidence",
                evidence_text=self.evidence_text_widget.get("1.0", tk.END),
                evidence_name=self.evidence_name_var.get().strip() or "execution-evidence",
                static_code=static_code,
            )

        if mode == "live":
            pid, target_label = self._resolve_process_target(
                self.live_pid_var.get(),
                self.live_process_name_var.get(),
                self.live_window_title_var.get(),
                allow_blank=True,
            )
            self.live_target_status_var.set(f"Target: {target_label}")
            duration = self._parse_int(self.live_duration_var.get(), "Duration seconds", allow_zero=True, default=30)
            return GuiTask(
                mode=mode,
                config=config,
                analyzers=analyzers,
                out_dir=out_dir,
                report_format=report_format,
                target_label=target_label,
                pid=pid,
                process_name=self.live_process_name_var.get().strip(),
                window_title=self.live_window_title_var.get().strip(),
                live_duration=duration,
                live_include_processes=self.live_include_processes_var.get(),
                live_include_threads=self.live_include_threads_var.get(),
                live_include_images=self.live_include_images_var.get(),
            )

        if mode == "memory":
            pid, target_label = self._resolve_process_target(
                self.pid_var.get(),
                self.process_name_var.get(),
                self.window_title_var.get(),
                allow_blank=False,
            )
            self.memory_target_status_var.set(f"Target: {target_label}")
            address = self.address_var.get().strip()
            if not address:
                raise ValueError("Address is required.")
            size = self._parse_int(self.size_var.get(), "Size", allow_zero=False, default=64)
            return GuiTask(
                mode=mode,
                config=config,
                analyzers=analyzers,
                out_dir=out_dir,
                report_format=report_format,
                target_label=target_label,
                pid=pid,
                process_name=self.process_name_var.get().strip(),
                window_title=self.window_title_var.get().strip(),
                address=address,
                size=size,
            )

        raise ValueError("No analysis tab selected.")

    def _load_config(self) -> TriageConfig:
        config_path_text = self.config_path_var.get().strip()
        if config_path_text:
            config_path = Path(config_path_text).expanduser()
            if not config_path.exists():
                raise ValueError(f"Config not found: {config_path}")
            config = load_config(config_path)
        else:
            config = TriageConfig()

        config.min_string = self._parse_int(self.min_string_var.get(), "Min string", allow_zero=False, default=config.min_string)
        config.max_strings = self._parse_int(
            self.max_strings_var.get(),
            "Max strings",
            allow_zero=False,
            default=config.max_strings,
        )

        native_probe_path = self.native_probe_var.get().strip()
        if native_probe_path:
            config.native_probe_path = native_probe_path

        perf_scan_path = self.perf_scan_var.get().strip()
        if perf_scan_path:
            config.perf_scan_path = perf_scan_path

        process_memory_path = self.process_memory_var.get().strip()
        if process_memory_path:
            config.process_memory_path = process_memory_path

        selected_analyzers = self._selected_analyzers()
        if selected_analyzers is not None:
            config.enabled_analyzers = selected_analyzers

        return config

    def _resolve_process_target(
        self,
        pid_text: str,
        process_name_text: str,
        window_title_text: str,
        *,
        allow_blank: bool,
    ) -> tuple[int | None, str]:
        pid = self._parse_optional_int(pid_text)
        candidate = resolve_process_candidate(
            pid=pid,
            process_name=process_name_text,
            window_title=window_title_text,
        )
        if candidate is None:
            if allow_blank:
                return None, "All processes"
            raise ValueError("PID, process name, or window title is required.")
        return candidate.pid, candidate.label()

    def _parse_optional_int(self, value: str) -> int | None:
        text = value.strip()
        if not text:
            return None
        return self._parse_int(text, "PID", allow_zero=False)

    def _describe_target(self, task: GuiTask) -> str:
        if task.mode == "live":
            return "All processes" if task.pid is None else f"PID {task.pid}"
        if task.mode == "memory":
            return "Memory target"
        return task.target_label or "Target"

    def _run_task(self, task: GuiTask) -> None:
        try:
            if task.mode == "file":
                result, written = analyze_and_write_reports(
                    target=task.target or Path(),
                    out_dir=task.out_dir,
                    report_format=task.report_format,
                    config=task.config,
                    analyzers=task.analyzers,
                )
            elif task.mode == "code":
                result, written = analyze_code_text_and_write_reports(
                    code=task.code_text,
                    out_dir=task.out_dir,
                    report_format=task.report_format,
                    target_name=task.code_name,
                    config=task.config,
                    analyzers=task.analyzers,
                )
            elif task.mode == "live":
                raise ValueError("Live mode must use the live worker.")
            elif task.mode == "evidence":
                result, written = analyze_execution_evidence_and_write_reports(
                    evidence=task.evidence_text,
                    out_dir=task.out_dir,
                    report_format=task.report_format,
                    static_code=task.static_code,
                    target_name=task.evidence_name,
                    config=task.config,
                    analyzers=task.analyzers,
                )
            elif task.mode == "memory":
                result, written = analyze_process_memory_and_write_reports(
                    pid=task.pid or 0,
                    address=task.address or "",
                    size=task.size,
                    out_dir=task.out_dir,
                    report_format=task.report_format,
                    config=task.config,
                    analyzers=task.analyzers,
                )
            else:
                raise ValueError(f"Unsupported mode: {task.mode}")
        except Exception as exc:
            self.message_queue.put(
                {
                    "type": "error",
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                }
            )
            return

        self.message_queue.put(
            {
                "type": "success",
                "mode": task.mode,
                "target": result.target,
                "issues": len(result.issues),
                "indicators": len(result.indicators),
                "written": [str(path) for path in written],
                "summary_lines": self._finding_summary_lines(result.findings),
            }
        )

    def _run_live_task(self, task: GuiTask, stop_event: threading.Event | None) -> None:
        try:
            event_count = 0
            for event in stream_live_kernel_events(
                process_id=task.pid,
                duration_seconds=task.live_duration or None,
                include_processes=task.live_include_processes,
                include_threads=task.live_include_threads,
                include_images=task.live_include_images,
                stop_event=stop_event,
            ):
                event_count += 1
                self.message_queue.put(
                    {
                        "type": "live_event",
                        "event": event.to_dict(),
                        "target": task.target_label,
                    }
                )

            self.message_queue.put(
                {
                    "type": "live_complete",
                    "target": task.target_label,
                    "events": event_count,
                    "stopped": bool(stop_event and stop_event.is_set()),
                }
            )
        except Exception as exc:
            self.message_queue.put(
                {
                    "type": "error",
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                }
            )

    def _active_mode(self) -> str:
        return self.mode_var.get()

    def _set_busy(self, busy: bool) -> None:
        self.run_button.configure(state="disabled" if busy else "normal")
        if busy and self.active_task_mode == "live":
            self.stop_button.configure(state="normal")
        else:
            self.stop_button.configure(state="disabled")
        if busy:
            self.status_var.set("Monitoring..." if self.active_task_mode == "live" else "Running...")
        else:
            self.status_var.set("Ready")

    def _poll_messages(self) -> None:
        while True:
            try:
                message = self.message_queue.get_nowait()
            except queue.Empty:
                break

            message_type = message.get("type")
            if message_type == "success":
                self._append_log(
                    f"Done: {message.get('target')} | issues={message.get('issues')} | "
                    f"indicators={message.get('indicators')}"
                )
                for line in message.get("summary_lines", []):
                    self._append_log(f"  {line}")
                for path in message.get("written", []):
                    self._append_log(f"  {path}")
                self.active_task_mode = None
                self._set_busy(False)
                self.worker_thread = None
            elif message_type == "live_event":
                event = message.get("event") or {}
                timestamp = event.get("timestamp", "")
                kind = event.get("kind", "unknown")
                summary = event.get("summary", "")
                self._append_log(f"[LIVE] {timestamp} {kind}: {summary}")
            elif message_type == "live_complete":
                stopped = bool(message.get("stopped"))
                event_count = message.get("events", 0)
                suffix = "stopped" if stopped else "finished"
                self._append_log(f"Live monitor {suffix}: {message.get('target')} ({event_count} events)")
                self.active_task_mode = None
                self.live_stop_event = None
                self._set_busy(False)
                self.worker_thread = None
            elif message_type == "error":
                self._append_log(f"Error: {message.get('message')}")
                details = message.get("traceback")
                if details:
                    self._append_log(str(details))
                self.active_task_mode = None
                self.live_stop_event = None
                self._set_busy(False)
                self.worker_thread = None
                self._show_error(str(message.get("message") or "Analysis failed."))

        self.root.after(100, self._poll_messages)

    def _append_log(self, text: str) -> None:
        tag = self._log_tag_for(text)
        self.log_widget.configure(state="normal")
        self.log_widget.insert(tk.END, text.rstrip() + "\n", tag)
        self.log_widget.see(tk.END)
        self.log_widget.configure(state="disabled")

    def _log_tag_for(self, text: str) -> str:
        if text.startswith("Error:"):
            return "error"
        if text.startswith("[LIVE]"):
            return "live"
        if text.startswith("Done:") or text.startswith("Live monitor"):
            return "success"
        return "meta"

    def clear_log(self) -> None:
        self.log_widget.configure(state="normal")
        self.log_widget.delete("1.0", tk.END)
        self.log_widget.configure(state="disabled")

    def stop_live_monitor(self) -> None:
        if self.live_stop_event is None:
            return
        self.live_stop_event.set()
        self.stop_button.configure(state="disabled")
        self.status_var.set("Stopping...")
        self._append_log("Stopping live monitor...")

    def open_output_dir(self) -> None:
        out_dir = Path(self.out_dir_var.get().strip() or "reports").expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(out_dir))  # type: ignore[attr-defined]
        except Exception as exc:
            self._show_error(f"Could not open output folder: {exc}")

    def _show_error(self, message: str) -> None:
        self.status_var.set("Error")
        self.notice_var.set(message)
        if hasattr(self, "notice_label"):
            self.notice_label.configure(style="Error.TLabel")
            self.notice_label.grid()

    def _show_notice(self, message: str) -> None:
        self.notice_var.set(message)
        if hasattr(self, "notice_label"):
            self.notice_label.configure(style="Notice.TLabel")
            self.notice_label.grid()

    def _clear_notice(self) -> None:
        self.notice_var.set("")
        if hasattr(self, "notice_label"):
            self.notice_label.grid_remove()

    def _validate_report_format(self, value: str) -> ReportFormat:
        if value not in {"all", "json", "markdown"}:
            raise ValueError(f"Unsupported report format: {value}")
        return value  # type: ignore[return-value]

    def _parse_int(self, value: str, label: str, *, allow_zero: bool, default: int | None = None) -> int:
        text = value.strip()
        if not text:
            if default is None:
                raise ValueError(f"{label} is required.")
            return default
        try:
            parsed = int(text, 0)
        except ValueError as exc:
            raise ValueError(f"Invalid {label}: {text}") from exc
        if parsed < 0 or (parsed == 0 and not allow_zero):
            raise ValueError(f"{label} must be greater than zero.")
        return parsed

    def _finding_summary_lines(self, findings: dict[str, Any]) -> list[str]:
        lines: list[str] = []
        max_lines = 12
        for name, finding in findings.items():
            if len(lines) >= max_lines:
                break

            summary_text, preview_lines = summarize_finding(finding, max_preview_items=3)
            if summary_text:
                lines.append(f"{name}: {summary_text}")
            for item in preview_lines[:3]:
                if len(lines) >= max_lines:
                    break
                lines.append(f"{name}: {item}")
        return lines


def main(argv: list[str] | None = None) -> int:
    if _TK_IMPORT_ERROR is not None or tk is None:
        print(f"GUI unavailable: {_TK_IMPORT_ERROR}", file=sys.stderr)
        return 2

    try:
        root = tk.Tk()
    except Exception as exc:
        print(f"GUI unavailable: {exc}", file=sys.stderr)
        return 2

    try:
        ReverseToolsApp(root)
        root.mainloop()
    except Exception as exc:
        print(f"GUI failed: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
