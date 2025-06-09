import ctypes
import os

lib = ctypes.CDLL(os.path.abspath("libxdp_socket.so"))

lib.xdp_open.argtypes = [ctypes.c_char_p]
lib.xdp_open.restype = ctypes.c_int

lib.xdp_recv.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
lib.xdp_recv.restype = ctypes.c_int

lib.xdp_close.argtypes = []
lib.xdp_close.restype = None

def xdp_open(interface: str) -> bool:
    return lib.xdp_open(interface.encode('utf-8')) == 0

def xdp_recv(max_size=2048) -> bytes:
    buf = ctypes.create_string_buffer(max_size)
    n = lib.xdp_recv(buf, max_size)
    return buf.raw[:n] if n > 0 else b''

def xdp_close():
    lib.xdp_close()
