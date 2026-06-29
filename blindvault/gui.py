"""BlindVault desktop app — the human owner's window into the vault.

This is the *human* side of the tool. On launch it asks for your master password
(or helps you create one). Unlike the AI-facing CLI, a person here is allowed to
reveal and copy values — it is their vault. The AI keeps using the command line
and still never sees plaintext.

Built on tkinter (bundled with Python), so the packaged .exe needs nothing else.
"""

from __future__ import annotations

import os
import sys
import tkinter as tk
from tkinter import messagebox, ttk

from . import resolver
from .crypto import AuthError, VaultError
from .service import SOURCE_GENERATED, Vault

APP_TITLE = "BlindVault"
CLIPBOARD_CLEAR_SECONDS = 20
MASK = "•" * 8


def _icon_file() -> str | None:
    """Locate blindvault.ico whether running from source or a PyInstaller bundle."""
    candidates = []
    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        candidates.append(os.path.join(bundled, "blindvault.ico"))
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, "..", "assets", "blindvault.ico"))
    candidates.append(os.path.join(here, "assets", "blindvault.ico"))
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


def _apply_icon(root: tk.Tk) -> None:
    path = _icon_file()
    if not path:
        return
    try:
        root.iconbitmap(default=path)  # default => inherited by all dialogs too
    except tk.TclError:
        pass


def _center_window(win: tk.Misc) -> None:
    """Place a window in the centre of the screen."""
    win.update_idletasks()
    w = win.winfo_width()
    h = win.winfo_height()
    if w <= 1:  # not realised yet — fall back to requested size
        w = win.winfo_reqwidth()
        h = win.winfo_reqheight()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x = max(0, (sw - w) // 2)
    y = max(0, (sh - h) // 2)
    win.geometry(f"+{x}+{y}")


# --------------------------------------------------------------------------- #
# small modal dialogs
# --------------------------------------------------------------------------- #
class _Dialog(tk.Toplevel):
    """Base modal dialog, centred on screen."""

    def __init__(self, parent: tk.Misc, title: str) -> None:
        super().__init__(parent)
        self._parent = parent
        self.withdraw()  # stay hidden until laid out and positioned (no flash, behind, or off-screen)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel())
        self.result = None
        self.body = ttk.Frame(self, padding=14)
        self.body.grid(row=0, column=0, sticky="nsew")
        # Present once subclasses have added their widgets AND the window is viewable, so
        # grab_set never fails ("window not viewable") and the dialog reliably appears in
        # front and on-screen — centred over the parent window (robust across DPI/monitors).
        self.after(0, self._present)

    def _present(self) -> None:
        try:
            self.update_idletasks()
            w, h = self.winfo_reqwidth(), self.winfo_reqheight()
            top = self._parent.winfo_toplevel()
            if top.winfo_viewable():
                x = top.winfo_rootx() + max(0, (top.winfo_width() - w) // 2)
                y = top.winfo_rooty() + max(0, (top.winfo_height() - h) // 2)
            else:
                x = max(0, (self.winfo_screenwidth() - w) // 2)
                y = max(0, (self.winfo_screenheight() - h) // 2)
            self.geometry(f"+{x}+{y}")
            self.deiconify()
            self.lift()
            self.grab_set()
            self.focus_force()
        except tk.TclError:
            pass

    def _buttons(self, ok_text: str = "Save") -> None:
        bar = ttk.Frame(self, padding=(14, 0, 14, 14))
        bar.grid(row=1, column=0, sticky="e")
        ttk.Button(bar, text="Cancel", command=self.destroy).grid(row=0, column=0, padx=4)
        ttk.Button(bar, text=ok_text, command=self._on_ok).grid(row=0, column=1, padx=4)
        self.bind("<Return>", lambda _e: self._on_ok())
        self.bind("<Escape>", lambda _e: self.destroy())

    def _on_ok(self) -> None:  # overridden
        raise NotImplementedError

    def show(self):
        self.wait_window()
        return self.result


class ChangePasswordDialog(_Dialog):
    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent, "Change master password")
        ttk.Label(self.body, text="Current").grid(row=0, column=0, sticky="w", pady=4)
        self.old = ttk.Entry(self.body, width=30, show="•")
        self.old.grid(row=0, column=1, pady=4)
        ttk.Label(self.body, text="New").grid(row=1, column=0, sticky="w", pady=4)
        self.new = ttk.Entry(self.body, width=30, show="•")
        self.new.grid(row=1, column=1, pady=4)
        ttk.Label(self.body, text="Confirm").grid(row=2, column=0, sticky="w", pady=4)
        self.confirm = ttk.Entry(self.body, width=30, show="•")
        self.confirm.grid(row=2, column=1, pady=4)
        self._buttons("Change")
        self.old.focus_set()

    def _on_ok(self) -> None:
        if not self.new.get():
            messagebox.showwarning(APP_TITLE, "Please enter a new password.", parent=self)
            return
        if self.new.get() != self.confirm.get():
            messagebox.showwarning(APP_TITLE, "New passwords do not match.", parent=self)
            return
        self.result = (self.old.get(), self.new.get())
        self.destroy()


class AddDialog(_Dialog):
    """Add a secret manually (name + value + optional note)."""

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent, "Add a secret")
        self._show = tk.BooleanVar(value=False)

        ttk.Label(self.body, text="Name").grid(row=0, column=0, sticky="w", pady=4)
        self.name = ttk.Entry(self.body, width=36)
        self.name.grid(row=0, column=1, columnspan=2, sticky="we", pady=4)

        ttk.Label(self.body, text="Value").grid(row=1, column=0, sticky="w", pady=4)
        self.value = ttk.Entry(self.body, width=36, show="•")
        self.value.grid(row=1, column=1, sticky="we", pady=4)
        ttk.Checkbutton(self.body, text="Show", variable=self._show,
                        command=self._toggle).grid(row=1, column=2, padx=(6, 0))

        ttk.Label(self.body, text="Note").grid(row=2, column=0, sticky="w", pady=4)
        self.desc = ttk.Entry(self.body, width=36)
        self.desc.grid(row=2, column=1, columnspan=2, sticky="we", pady=4)

        self._buttons("Add")
        self.name.focus_set()

    def _toggle(self) -> None:
        self.value.configure(show="" if self._show.get() else "•")

    def _on_ok(self) -> None:
        name = self.name.get().strip()
        value = self.value.get()
        if not name:
            messagebox.showwarning(APP_TITLE, "Please enter a name.", parent=self)
            return
        if not value:
            messagebox.showwarning(APP_TITLE, "Please enter a value.", parent=self)
            return
        self.result = (name, value, self.desc.get().strip())
        self.destroy()


class GenerateDialog(_Dialog):
    """Generate a random secret without anyone seeing it."""

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent, "Generate a secret")

        ttk.Label(self.body, text="Name").grid(row=0, column=0, sticky="w", pady=4)
        self.name = ttk.Entry(self.body, width=32)
        self.name.grid(row=0, column=1, sticky="we", pady=4)

        ttk.Label(self.body, text="Length").grid(row=1, column=0, sticky="w", pady=4)
        self.length = ttk.Spinbox(self.body, from_=8, to=128, width=8)
        self.length.set(32)
        self.length.grid(row=1, column=1, sticky="w", pady=4)

        ttk.Label(self.body, text="Note").grid(row=2, column=0, sticky="w", pady=4)
        self.desc = ttk.Entry(self.body, width=32)
        self.desc.grid(row=2, column=1, sticky="we", pady=4)

        ttk.Label(self.body, text="The value is created and stored without being shown.",
                  foreground="#555").grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))

        self._buttons("Generate")
        self.name.focus_set()

    def _on_ok(self) -> None:
        name = self.name.get().strip()
        if not name:
            messagebox.showwarning(APP_TITLE, "Please enter a name.", parent=self)
            return
        try:
            length = int(self.length.get())
        except ValueError:
            messagebox.showwarning(APP_TITLE, "Length must be a number.", parent=self)
            return
        self.result = (name, length, self.desc.get().strip())
        self.destroy()


class RevealDialog(_Dialog):
    """Show a plaintext value with copy-to-clipboard (auto-clearing)."""

    def __init__(self, parent: tk.Misc, name: str, value: str) -> None:
        super().__init__(parent, f"Reveal: {name}")
        self._value = value
        self._show = tk.BooleanVar(value=False)

        ttk.Label(self.body, text=name, font=("", 10, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        self.entry = ttk.Entry(self.body, width=44, show="•")
        self.entry.insert(0, value)
        self.entry.configure(state="readonly")
        self.entry.grid(row=1, column=0, columnspan=2, sticky="we", pady=8)

        ttk.Checkbutton(self.body, text="Show value", variable=self._show,
                        command=self._toggle).grid(row=2, column=0, sticky="w")

        bar = ttk.Frame(self, padding=(14, 0, 14, 14))
        bar.grid(row=1, column=0, sticky="e")
        ttk.Button(bar, text="Copy", command=self._copy).grid(row=0, column=0, padx=4)
        ttk.Button(bar, text="Close", command=self.destroy).grid(row=0, column=1, padx=4)
        self.bind("<Escape>", lambda _e: self.destroy())

    def _toggle(self) -> None:
        self.entry.configure(show="" if self._show.get() else "•")

    def _copy(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self._value)
        self.after(CLIPBOARD_CLEAR_SECONDS * 1000, self._clear_clipboard)
        messagebox.showinfo(
            APP_TITLE,
            f"Copied. The clipboard will be cleared in {CLIPBOARD_CLEAR_SECONDS}s.",
            parent=self,
        )

    def _clear_clipboard(self) -> None:
        try:
            if self.clipboard_get() == self._value:
                self.clipboard_clear()
        except tk.TclError:
            pass


class _NoteDialog(_Dialog):
    def __init__(self, parent: tk.Misc, name: str, current: str) -> None:
        super().__init__(parent, f"Note: {name}")
        ttk.Label(self.body, text="Description").grid(row=0, column=0, sticky="w")
        self.entry = ttk.Entry(self.body, width=40)
        self.entry.insert(0, current)
        self.entry.grid(row=1, column=0, pady=6)
        self._buttons("Save")
        self.entry.focus_set()

    def _on_ok(self) -> None:
        self.result = self.entry.get().strip()
        self.destroy()


# --------------------------------------------------------------------------- #
# main window
# --------------------------------------------------------------------------- #
class App(ttk.Frame):
    COLUMNS = ("name", "password", "description", "updated")

    def __init__(self, master: tk.Tk, vault: Vault) -> None:
        super().__init__(master, padding=10)
        self.master = master
        self.vault = vault
        self._data_key = vault.data_key  # kept in memory to re-open on refresh
        self.grid(row=0, column=0, sticky="nsew")
        master.rowconfigure(0, weight=1)
        master.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self.columnconfigure(0, weight=1)

        self._build_toolbar()
        self._build_search()
        self._build_table()
        self._build_status()
        self.refresh()

    # -- layout ----------------------------------------------------------- #
    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self)
        bar.grid(row=0, column=0, sticky="we", pady=(0, 8))
        buttons = [
            ("Add", self.on_add),
            ("Generate", self.on_generate),
            ("Reveal", self.on_reveal),
            ("Edit note", self.on_edit_note),
            ("Delete", self.on_delete),
            ("Refresh", self.refresh),
            ("Change password", self.on_change_password),
        ]
        for i, (label, cmd) in enumerate(buttons):
            ttk.Button(bar, text=label, command=cmd).grid(row=0, column=i, padx=(0, 6))

    def _build_search(self) -> None:
        row = ttk.Frame(self)
        row.grid(row=1, column=0, sticky="we", pady=(0, 6))
        ttk.Label(row, text="Filter").grid(row=0, column=0, padx=(0, 6))
        self.query = tk.StringVar()
        self.query.trace_add("write", lambda *_: self._render())
        ttk.Entry(row, textvariable=self.query, width=36).grid(row=0, column=1, sticky="w")
        ttk.Label(
            row,
            text="Tip: click a Name to copy an AI instruction · click a Password to copy its value",
            foreground="#888",
        ).grid(row=0, column=2, padx=(12, 0), sticky="w")

    def _build_table(self) -> None:
        wrap = ttk.Frame(self)
        wrap.grid(row=2, column=0, sticky="nsew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(wrap, columns=self.COLUMNS, show="headings", selectmode="browse")
        headings = {
            "name": ("Name  (click to copy AI instruction)", 280),
            "password": ("Password  (click to copy)", 180),
            "description": ("Description", 240),
            "updated": ("Updated", 170),
        }
        for col, (text, width) in headings.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor="w")
        self.tree.tag_configure("generated", foreground="#0a6")
        self.tree.grid(row=0, column=0, sticky="nsew")

        scroll = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")

        # Single click: copy the AI instruction (Name) or the value (Password).
        self.tree.bind("<ButtonRelease-1>", self._on_click)

    def _build_status(self) -> None:
        self.status = tk.StringVar()
        ttk.Label(self, textvariable=self.status, foreground="#555", anchor="w").grid(
            row=3, column=0, sticky="we", pady=(8, 0)
        )

    # -- data ------------------------------------------------------------- #
    def refresh(self) -> None:
        try:
            vault = Vault.open_locked()
            vault.unlock_with_data_key(self._data_key)
            self.vault = vault
        except VaultError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self._rows = self.vault.entries()
        self._render()

    def _render(self) -> None:
        needle = self.query.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        shown = 0
        for row in self._rows:
            haystack = f"{row['name']} {row['description']}".lower()
            if needle and needle not in haystack:
                continue
            generated = row["source"] == SOURCE_GENERATED
            # The Password column shows only a mask; the real value is copied on click.
            self.tree.insert(
                "", "end",
                values=(row["name"], MASK, row["description"], row["updated"]),
                tags=("generated",) if generated else (),
            )
            shown += 1
        suffix = f"  (showing {shown})" if needle else ""
        self.status.set(self._base_status() + suffix)

    def _base_status(self) -> str:
        return f"{len(self._rows)} secret(s) in {Vault.location()}"

    def _flash(self, message: str) -> None:
        self.status.set(message)
        self.after(5000, lambda: self.status.set(self._base_status()))

    def _set_clipboard(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)

    def _clear_clipboard_if(self, value: str) -> None:
        try:
            if self.clipboard_get() == value:
                self.clipboard_clear()
        except tk.TclError:
            pass

    def _selected_name(self) -> str | None:
        sel = self.tree.selection()
        if not sel:
            return None
        return self.tree.item(sel[0], "values")[0]

    # -- click-to-copy ---------------------------------------------------- #
    def _on_click(self, event) -> None:
        if self.tree.identify("region", event.x, event.y) != "cell":
            return
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return
        try:
            idx = int(self.tree.identify_column(event.x).replace("#", "")) - 1
        except ValueError:
            return
        if not (0 <= idx < len(self.COLUMNS)):
            return
        name = self.tree.item(row_id, "values")[0]
        column = self.COLUMNS[idx]
        if column == "name":
            self._copy_reference(name)
        elif column == "password":
            self._copy_value(name)

    def _copy_reference(self, name: str) -> None:
        self._set_clipboard(resolver.prompt_instruction(name))
        self._flash(f'Copied an AI instruction for "{name}" — paste it into your agent prompt.')

    def _copy_value(self, name: str) -> None:
        try:
            value = self.vault.reveal(name)
        except VaultError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self._set_clipboard(value)
        self.after(CLIPBOARD_CLEAR_SECONDS * 1000, lambda v=value: self._clear_clipboard_if(v))
        self._flash(f'Copied the value of "{name}". Clipboard clears in {CLIPBOARD_CLEAR_SECONDS}s.')

    # -- actions ---------------------------------------------------------- #
    def on_add(self) -> None:
        result = AddDialog(self).show()
        if not result:
            return
        name, value, desc = result
        if self.vault.exists(name) and not messagebox.askyesno(
            APP_TITLE, f"'{name}' already exists. Overwrite it?"
        ):
            return
        try:
            self.vault.add(name, value, desc)
        except VaultError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self.refresh()

    def on_generate(self) -> None:
        result = GenerateDialog(self).show()
        if not result:
            return
        name, length, desc = result
        if self.vault.exists(name) and not messagebox.askyesno(
            APP_TITLE, f"'{name}' already exists. Overwrite it?"
        ):
            return
        try:
            self.vault.generate(name, length=length, description=desc)
        except VaultError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self.refresh()

    def on_reveal(self) -> None:
        name = self._selected_name()
        if not name:
            messagebox.showinfo(APP_TITLE, "Select a secret first.")
            return
        try:
            value = self.vault.reveal(name)
        except VaultError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        RevealDialog(self, name, value)

    def on_edit_note(self) -> None:
        name = self._selected_name()
        if not name:
            messagebox.showinfo(APP_TITLE, "Select a secret first.")
            return
        current = next((r["description"] for r in self._rows if r["name"] == name), "")
        new = _NoteDialog(self, name, current).show()
        if new is None:
            return
        try:
            self.vault.set_description(name, new)
        except VaultError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self.refresh()

    def on_delete(self) -> None:
        name = self._selected_name()
        if not name:
            messagebox.showinfo(APP_TITLE, "Select a secret first.")
            return
        if not messagebox.askyesno(APP_TITLE, f"Delete '{name}'? This cannot be undone."):
            return
        try:
            self.vault.delete(name)
        except VaultError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self.refresh()

    def on_change_password(self) -> None:
        result = ChangePasswordDialog(self).show()
        if not result:
            return
        old, new = result
        try:
            self.vault.change_password(old, new)
        except AuthError:
            messagebox.showerror(APP_TITLE, "Current password is incorrect.")
            return
        except VaultError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        messagebox.showinfo(APP_TITLE, "Master password changed.")


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #
def _enable_dpi_awareness() -> None:
    try:  # crisp text on Windows; harmless elsewhere
        from ctypes import windll

        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


class LoginView(ttk.Frame):
    """The first screen: create, unlock, or upgrade — shown in the root window.

    Building this directly in the (visible) root avoids the earlier bug where a
    dialog shown over a withdrawn root never appeared on Windows.
    """

    def __init__(self, master: tk.Tk, on_success) -> None:
        super().__init__(master, padding=28)
        self._on_success = on_success
        self.grid(row=0, column=0)
        master.rowconfigure(0, weight=1)
        master.columnconfigure(0, weight=1)
        self._error = tk.StringVar()

        if Vault.is_legacy_v1():
            self._mode = "migrate"
        elif Vault.is_initialized():
            self._mode = "unlock"
        else:
            self._mode = "create"
        self._build()

    def _build(self) -> None:
        if self._mode == "unlock":
            title, intro, button = "Unlock BlindVault", "Enter your master password.", "Unlock"
            need_confirm = False
        elif self._mode == "create":
            title = "Create your vault"
            intro = "Choose a master password.\nIt encrypts your vault and cannot be recovered."
            button, need_confirm = "Create", True
        else:  # migrate
            count = len(Vault.legacy_names())
            title = "Upgrade your vault"
            intro = (f"Found {count} secret(s) in an older, unencrypted vault.\n"
                     "Set a master password to encrypt them.")
            button, need_confirm = "Upgrade", True

        ttk.Label(self, text=title, font=("", 13, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 6))
        ttk.Label(self, text=intro, justify="center", foreground="#555").grid(
            row=1, column=0, columnspan=2, pady=(0, 14))

        ttk.Label(self, text="Password").grid(row=2, column=0, sticky="w", pady=4)
        self._pw = ttk.Entry(self, width=30, show="•")
        self._pw.grid(row=2, column=1, pady=4)

        self._confirm = None
        if need_confirm:
            ttk.Label(self, text="Confirm").grid(row=3, column=0, sticky="w", pady=4)
            self._confirm = ttk.Entry(self, width=30, show="•")
            self._confirm.grid(row=3, column=1, pady=4)

        ttk.Label(self, textvariable=self._error, foreground="#c00").grid(
            row=4, column=0, columnspan=2, pady=(6, 0))
        ttk.Button(self, text=button, command=self._submit).grid(
            row=5, column=0, columnspan=2, pady=(12, 0))

        self.bind_all("<Return>", lambda _e: self._submit())
        self._pw.focus_set()

    def _submit(self) -> None:
        password = self._pw.get()
        if not password:
            self._error.set("Please enter a password.")
            return
        if self._confirm is not None and password != self._confirm.get():
            self._error.set("Passwords do not match.")
            return
        try:
            if self._mode == "unlock":
                vault = Vault.open_locked().unlock_with_password(password)
            elif self._mode == "create":
                Vault.initialize(password)
                vault = Vault.open_locked().unlock_with_password(password)
            else:  # migrate
                Vault.migrate_from_v1(password)
                vault = Vault.open_locked().unlock_with_password(password)
        except AuthError:
            self._error.set("Wrong master password. Please try again.")
            self._pw.delete(0, "end")
            return
        except VaultError as exc:
            self._error.set(str(exc))
            return
        self.unbind_all("<Return>")
        self._on_success(vault)


def main() -> int:
    _enable_dpi_awareness()
    root = tk.Tk()
    root.title(APP_TITLE)
    root.minsize(440, 280)
    _apply_icon(root)

    def on_success(vault: Vault) -> None:
        for child in root.winfo_children():
            child.destroy()
        root.minsize(960, 460)
        App(root, vault)
        root.update_idletasks()
        _center_window(root)

    LoginView(root, on_success)
    root.update_idletasks()
    _center_window(root)
    root.lift()
    try:
        root.focus_force()
    except tk.TclError:
        pass
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
