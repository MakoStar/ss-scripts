# -*- coding: utf-8 -*-
# auto install ca cert and manage windows system proxy, windows only
import ctypes
import logging
import os
import subprocess

if os.name == "nt":
    import winreg

# internet settings registry hive
PROXY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# process name fragments of common game accelerators
ACCELERATORS = ["uu", "leigod", "timplat", "nattyp", "raylink"]


def is_windows():
    return os.name == "nt"


# wininet default connection settings flag for wpad auto detect
AUTODETECT_FLAG = 0x08


def _reg_set(name, value, rtype):
    # write one internet settings value
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PROXY_PATH, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, name, 0, rtype, value)
        winreg.CloseKey(k)
        return True
    except OSError as e:
        logging.warning("SS auto proxy write %s failed: %s" % (name, e))
        return False


def _reg_get(name):
    # read one internet settings value, returns raw value or None
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PROXY_PATH, 0, winreg.KEY_QUERY_VALUE)
        v, _ = winreg.QueryValueEx(k, name)
        winreg.CloseKey(k)
        return v
    except OSError:
        return None


def _autodetect_off():
    # clear the wpad flag inside DefaultConnectionSettings
    raw = _reg_get("DefaultConnectionSettings")
    if isinstance(raw, (bytes, bytearray)) and len(raw) >= 9:
        d = bytearray(raw)
        if d[8] & AUTODETECT_FLAG:
            d[8] &= 0xFF ^ AUTODETECT_FLAG
            _reg_set("DefaultConnectionSettings", bytes(d), winreg.REG_BINARY)
            return True
    return False


def _autodetect_restore(raw):
    # write the saved DefaultConnectionSettings back
    if isinstance(raw, (bytes, bytearray)) and len(raw) >= 9:
        _reg_set("DefaultConnectionSettings", bytes(raw), winreg.REG_BINARY)


def refresh():
    # broadcast proxy changes so browsers pick them up at once
    try:
        opt = ctypes.windll.wininet.InternetSetOptionW
        opt(None, 39, None, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        opt(None, 37, None, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass


def install_cert():
    # import the mitmproxy ca cert into the user trusted root store
    cert = os.path.join(os.path.expanduser("~"), ".mitmproxy", "mitmproxy-ca-cert.cer")
    if not os.path.exists(cert):
        logging.warning("SS auto cert not found, start mitmproxy once then retry: %s" % cert)
        return False
    r = subprocess.run(["certutil", "-addstore", "-user", "Root", cert],
                       capture_output=True, check=False)
    ok = r.returncode == 0
    logging.info("SS auto cert install " + ("ok" if ok else "failed, install %s manually" % cert))
    return ok


def backup_proxy():
    # keep the previous proxy settings for restore
    return {
        "ProxyEnable": _reg_get("ProxyEnable"),
        "ProxyServer": _reg_get("ProxyServer"),
        "DefaultConnectionSettings": _reg_get("DefaultConnectionSettings"),
    }


def apply_proxy(port):
    # point the system proxy at mitmproxy and disable auto detect
    _reg_set("ProxyEnable", 1, winreg.REG_DWORD)
    _reg_set("ProxyServer", "127.0.0.1:%d" % port, winreg.REG_SZ)
    _reg_set("ProxyOverride", "<local>", winreg.REG_SZ)
    _autodetect_off()
    refresh()
    logging.info("SS auto proxy set to 127.0.0.1:%d, auto detect off" % port)


def restore_proxy(backup):
    # put the previous proxy settings back
    if not backup:
        return
    enable = backup.get("ProxyEnable")
    server = backup.get("ProxyServer")
    _reg_set("ProxyEnable", int(enable or 0), winreg.REG_DWORD)
    if enable and server:
        _reg_set("ProxyServer", str(server), winreg.REG_SZ)
    _autodetect_restore(backup.get("DefaultConnectionSettings"))
    refresh()
    logging.info("SS auto proxy restored, enable=%s" % enable)


def check_accelerators():
    # warn when a game accelerator is running since it takes traffic away
    try:
        r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                           capture_output=True, check=False)
        low = r.stdout.decode("gbk", "ignore").lower()
        for name in ACCELERATORS:
            if name in low:
                logging.warning("SS auto proxy: accelerator process '%s' detected, "
                                "close it or traffic will bypass mitmproxy" % name)
                return
    except Exception:
        pass


def setup(port):
    # full auto setup at addon load, returns the backup for restore
    if not is_windows():
        logging.info("SS auto proxy skipped, not windows")
        return None
    install_cert()
    check_accelerators()
    backup = backup_proxy()
    apply_proxy(port)
    return backup


def restore(backup):
    # full restore at addon shutdown
    if not is_windows() or not backup:
        return
    restore_proxy(backup)
