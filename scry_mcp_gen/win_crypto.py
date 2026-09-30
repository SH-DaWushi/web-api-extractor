# -*- coding: utf-8 -*-
"""Windows DPAPI 加解密助手（只用标准库 ``ctypes``，不引入任何第三方依赖）。

**为什么需要它**：``auth.py`` 的 ``http_login`` 过去把账号与密码**明文**写进
``auth_states/<site_key>.json``。那份文件是长期留存的登录态（后续 ``start_capture``
直接复用，还可能被备份、同步、截图），凭据落进去就等于泄露。既然「存下账号密码、
下次自动复用」这个能力要保留，落盘的那一份就必须只有**同一台机器上的同一个
Windows 用户**能解开——这正是 DPAPI（``CryptProtectData`` / ``CryptUnprotectData``）
的用途，而它随 Windows 自带，不必把仓库的运行时依赖从三个变成四个。

**约定**：

* 一律使用**用户作用域**（不传 ``CRYPTPROTECT_LOCAL_MACHINE``）：只有同一
  Windows 用户能解密，同机其他用户拿到密文也解不开。
* ``available()`` 在非 Windows（或 crypt32 不可用）时返回 ``False``，**不抛异常**，
  由调用方自行决定降级策略——但降级**绝不能**是「回退成明文落盘」。
* 失败一律抛 ``DPAPIError``（带函数名与 Windows 错误码），不返回 ``None``、
  不静默吞掉：调用方必须能分辨「加密成功了」和「其实没加密」。
* ``CryptProtectData`` / ``CryptUnprotectData`` 的输出缓冲区归调用者所有，必须用
  ``LocalFree`` 释放——不释放就是真实的内存泄漏，这里用 ``finally`` 保证释放。
"""
from __future__ import annotations

import ctypes
import sys

_IS_WINDOWS = sys.platform == "win32"


class DPAPIError(RuntimeError):
    """DPAPI 加解密失败（平台不可用、API 返回 FALSE、密文不可解等）。"""


class _DataBlob(ctypes.Structure):
    """``DATA_BLOB``。

    字段用 ``c_uint32`` / ``c_void_p`` 显式声明，而不是 ``ctypes.wintypes.DWORD``：
    ``ctypes.wintypes`` 在非 Windows 上 import 即报错，而本模块在非 Windows 上
    也必须能被 import（只是 ``available()`` 返回 False）。
    显式声明同时避免了 64 位下指针被默认 ``c_int`` 截断。
    """

    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.c_void_p)]


_CRYPT32_SIGNATURE = [
    ctypes.POINTER(_DataBlob),  # pDataIn
    ctypes.c_wchar_p,           # szDataDescr
    ctypes.c_void_p,            # pOptionalEntropy
    ctypes.c_void_p,            # pvReserved
    ctypes.c_void_p,            # pPromptStruct
    ctypes.c_uint32,            # dwFlags（0 = 用户作用域）
    ctypes.POINTER(_DataBlob),  # pDataOut
]


def available() -> bool:
    """DPAPI 在当前平台能否使用；非 Windows 返回 ``False``（不抛异常）。"""
    if not _IS_WINDOWS:
        return False
    try:
        ctypes.windll.crypt32  # 缺失/加载失败会在这里抛错
    except (AttributeError, OSError):
        return False
    return True


def _call(function_name: str, data: bytes) -> bytes:
    """调用 crypt32 的 ``CryptProtectData`` / ``CryptUnprotectData``。

    两个函数的签名一致（只差语义），因此共用一份实现：输入一个 ``DATA_BLOB``、
    输出另一个 ``DATA_BLOB``，输出缓冲区由我们负责 ``LocalFree``。
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{function_name} 需要 bytes，收到 {type(data).__name__}")
    if not available():
        raise DPAPIError(f"DPAPI 不可用（当前平台：{sys.platform}）")

    # create_string_buffer 会拷贝一份并保证末尾有 NUL；cbData 只算真实长度。
    buf = ctypes.create_string_buffer(bytes(data))
    blob_in = _DataBlob(len(data), ctypes.cast(buf, ctypes.c_void_p))
    blob_out = _DataBlob()

    function = getattr(ctypes.windll.crypt32, function_name)
    function.argtypes = _CRYPT32_SIGNATURE
    function.restype = ctypes.c_int  # BOOL

    ok = function(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise DPAPIError(f"{function_name} 失败：Windows 错误码 {ctypes.windll.kernel32.GetLastError()}")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        # 不释放这块内存就是真实泄漏；blob_out 由 API 分配，必须交回 LocalFree。
        # 必须显式声明参数为指针：LocalFree 的默认参数类型是 c_int，64 位下
        # 直接传 pbData（整数地址）会 OverflowError——那会在 finally 里二次抛错，
        # 把真正的返回值/异常盖掉。
        local_free = ctypes.windll.kernel32.LocalFree
        local_free.argtypes = [ctypes.c_void_p]
        local_free.restype = ctypes.c_void_p
        local_free(blob_out.pbData)


def protect(data: bytes) -> bytes:
    """用当前 Windows 用户的 DPAPI 密钥加密。其他用户/机器无法解密。"""
    return _call("CryptProtectData", data)


def unprotect(blob: bytes) -> bytes:
    """解密 :func:`protect` 产出的密文；失败抛 :class:`DPAPIError`。"""
    return _call("CryptUnprotectData", blob)
