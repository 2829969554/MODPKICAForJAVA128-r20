# -*- coding: utf-8 -*-
import ctypes, subprocess, csv, io

out = subprocess.check_output('tasklist /FI "IMAGENAME eq java.exe" /FO CSV', text=True)
rows = list(csv.reader(io.StringIO(out)))
pids = [r[1] for r in rows[1:] if len(r) >= 2 and r[1].strip().isdigit()]
print("found pids:", pids)
kernel32 = ctypes.windll.kernel32
for pid in pids:
    h = kernel32.OpenProcess(0x0001, False, int(pid))
    if h:
        kernel32.TerminateProcess(h, 1)
        kernel32.CloseHandle(h)
        print("killed", pid)
    else:
        print("open fail", pid)
