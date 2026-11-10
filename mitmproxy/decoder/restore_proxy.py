# -*- coding: utf-8 -*-
# turn off the windows system proxy without starting mitmproxy
# usage uv run python decoder/restore_proxy.py
import ctypes
import os

if os.name != "nt":
    raise SystemExit("windows only")

import winreg

PROXY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def main():
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PROXY_PATH, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    winreg.CloseKey(k)
    try:
        opt = ctypes.windll.wininet.InternetSetOptionW
        opt(None, 39, None, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        opt(None, 37, None, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass
    print("system proxy disabled")


if __name__ == "__main__":
    main()
