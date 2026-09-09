#!/usr/bin/env python3
"""
Entry point for the packaged bot exe.

Double-click (no arguments)  -> opens the GUI (cc_gui). The GUI captures your
                                login on first run, then Start/Stop runs the bot
                                and drives it (market search, scan, live log).

Power-user / internal arguments still work, so the exe is also the full CLI and
the GUI can relaunch it headlessly:

    cubic-bot.exe                 # GUI (default)
    cubic-bot.exe gui             # GUI, explicitly
    cubic-bot.exe setup           # capture/replace the login in the console
    cubic-bot.exe live  ...       # run the bot headless (what the GUI spawns)
    cubic-bot.exe replay <cap> --key <hex>

All state (login profile, market DB, watchlist, ...) lives in %APPDATA%\\CubicBot
so a --onefile temp unpack never eats it.
"""
import os
import sys


def _ensure_std_streams():
    """A --windowed (no-console) frozen exe can start with sys.stdout/err set to
    None; cc_client prints constantly, so bind them to real fds (or devnull) to
    keep print() from crashing. In the GUI-spawned child, fd 1/2 point at the
    log file the GUI opened, so this also routes the bot's output there."""
    for name, fd in (("stdout", 1), ("stderr", 2)):
        if getattr(sys, name, None) is None:
            stream = None
            try:
                stream = os.fdopen(fd, "w", buffering=1, encoding="utf-8",
                                   errors="replace")
            except Exception:
                try:
                    stream = open(os.devnull, "w")
                except Exception:
                    stream = None
            if stream is not None:
                setattr(sys, name, stream)


def main():
    argv = sys.argv[1:]
    cmd = argv[0].lower() if argv else ""

    # GUI is the default face of the exe.
    if not argv or cmd == "gui":
        import cc_gui
        return cc_gui.run()

    # Console login capture (GUI has its own; this is the CLI fallback).
    if cmd in ("setup", "provision", "login"):
        import cc_provision
        prof = os.path.join(cc_provision.app_dir(), "cc_profile.json")
        ok = cc_provision.provision(prof)
        return 0 if ok else 1

    # Everything else is the full bot CLI (this is what the GUI relaunches for
    # its headless bot process: `live --control-port ...`).
    import cc_client
    sys.argv = [sys.argv[0]] + argv
    return cc_client.main() or 0


if __name__ == "__main__":
    _ensure_std_streams()
    sys.exit(main())
