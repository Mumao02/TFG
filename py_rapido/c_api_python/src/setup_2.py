from setuptools import setup, Extension

module_xdp = Extension(
    "xdp",
    sources=["xdp_socket.c"],  # o el archivo que estés usando
    libraries=["bpf"],
    extra_compile_args=["-O2", "-Wall", "-std=gnu11"],
)

setup(
    name="xdp",
    version="0.1",
    description="Modulo para recibir paquetes XDP con PyCapsule",
    ext_modules=[module_xdp],
)
