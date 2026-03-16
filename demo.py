"""Demo GUI app for requests-schannel.

A simple tkinter application that makes HTTPS requests using the
SchannelAdapter (Windows SChannel TLS) and displays the response.
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import scrolledtext, ttk

import requests

from requests_schannel.adapters import SchannelAdapter


class DemoApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("requests-schannel Demo")
        self.geometry("800x600")
        self.minsize(600, 400)

        self._session = requests.Session()
        self._session.mount("https://", SchannelAdapter())

        self._build_ui()

    # ── UI construction ──────────────────────────────────────────

    def _build_ui(self) -> None:
        # Top bar: URL entry + Go button
        top = ttk.Frame(self, padding=8)
        top.pack(fill=tk.X)

        ttk.Label(top, text="URL:").pack(side=tk.LEFT)
        self._url_var = tk.StringVar(value="https://www.howsmyssl.com/a/check")
        url_entry = ttk.Entry(top, textvariable=self._url_var)
        url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 6))
        url_entry.bind("<Return>", lambda _: self._on_go())

        self._go_btn = ttk.Button(top, text="Go", command=self._on_go)
        self._go_btn.pack(side=tk.LEFT)

        # Status bar
        self._status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self, textvariable=self._status_var, relief=tk.SUNKEN, anchor=tk.W, padding=4)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # Response headers + body in a PanedWindow
        pane = ttk.PanedWindow(self, orient=tk.VERTICAL)
        pane.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 4))

        # Headers section
        hdr_frame = ttk.LabelFrame(pane, text="Response Headers", padding=4)
        self._headers_text = scrolledtext.ScrolledText(hdr_frame, height=8, state=tk.DISABLED, wrap=tk.WORD)
        self._headers_text.pack(fill=tk.BOTH, expand=True)
        pane.add(hdr_frame, weight=1)

        # Body section
        body_frame = ttk.LabelFrame(pane, text="Response Body", padding=4)
        self._body_text = scrolledtext.ScrolledText(body_frame, height=16, state=tk.DISABLED, wrap=tk.WORD)
        self._body_text.pack(fill=tk.BOTH, expand=True)
        pane.add(body_frame, weight=3)

    # ── Request logic (runs on a background thread) ──────────────

    def _on_go(self) -> None:
        url = self._url_var.get().strip()
        if not url:
            return
        self._go_btn.config(state=tk.DISABLED)
        self._status_var.set(f"Requesting {url} …")
        self._set_text(self._headers_text, "")
        self._set_text(self._body_text, "")
        threading.Thread(target=self._do_request, args=(url,), daemon=True).start()

    def _do_request(self, url: str) -> None:
        try:
            resp = self._session.get(url, timeout=30)
            headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            status_line = f"{resp.status_code} {resp.reason}"
            self.after(0, self._show_result, status_line, headers, resp.text)
        except Exception as exc:
            self.after(0, self._show_error, str(exc))

    # ── UI update helpers (always called on the main thread) ─────

    def _show_result(self, status_line: str, headers: str, body: str) -> None:
        self._status_var.set(f"Done — {status_line}")
        self._set_text(self._headers_text, headers)
        self._set_text(self._body_text, body)
        self._go_btn.config(state=tk.NORMAL)

    def _show_error(self, message: str) -> None:
        self._status_var.set(f"Error — {message}")
        self._set_text(self._body_text, message)
        self._go_btn.config(state=tk.NORMAL)

    @staticmethod
    def _set_text(widget: scrolledtext.ScrolledText, text: str) -> None:
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.config(state=tk.DISABLED)

    def destroy(self) -> None:
        self._session.close()
        super().destroy()


if __name__ == "__main__":
    DemoApp().mainloop()
