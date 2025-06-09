from setuptools import setup, Extension

module = Extension("pcap_wrapper", sources=["pcap_wrapper.c"], libraries=["pcap"])

setup(
    name="pcap_wrapper",
    version="1.0",
    description="Wrapper en C para libpcap",
    ext_modules=[module],
)

