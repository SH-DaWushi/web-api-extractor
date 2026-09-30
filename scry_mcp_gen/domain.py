# -*- coding: utf-8 -*-
"""域名工具：可注册域解析与 RFC6265 Cookie 域匹配。

此前的实现散落在 auth.py 与 capture.py 两处，且都用「取末两段」当站点区域：

    target_zone = ".".join(target_host.split(".")[-2:])

对 `crm.example.com.cn` 这类主机名，末两段得到 **`com.cn`**——这是**公共后缀**，
不是可注册域（应为 `example.com.cn`）。判定因此过于宽松：任一 `.com.cn` 下的
第三方 Cookie 都可能被误判为目标站凭据。

本模块统一两处实现，并改用「公共后缀感知」的可注册域解析。
不引入第三方依赖（publicsuffix2 等），内置覆盖常见 ccTLD 二级后缀
与常见多段公共后缀。
"""
from __future__ import annotations

# 常见 ccTLD 下的二级公共后缀（形如 xxx.com.cn 中的 com.cn）。
# 用于把「末 N 段」修正为可注册域。列表不求穷尽，覆盖常见场景即可；
# 未收录的后缀退化为「取末两段」，与旧行为一致，不会更差。
_SECOND_LEVEL_SUFFIXES = frozenset({
    # 中国
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
    # 英国 / 澳洲 / 新西兰 / 日本 / 韩国 / 巴西 / 印度 / 南非
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "geek.nz", "school.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "ac.kr",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "gov.in", "edu.in",
    "co.za", "net.za", "org.za", "gov.za", "ac.za",
    # 港台
    "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk", "idv.hk",
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw",
    # 其他常见
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "co.th", "or.th", "ac.th", "go.th", "in.th",
    "com.mx", "com.ar", "com.tr", "com.ru", "com.ua", "com.pl",
    "co.il", "com.es", "com.pt", "com.gr", "com.vn", "com.ph", "com.id",
})

# 本身就是公共后缀的多段后缀（极少数），整段不应作为可注册域
_PUBLIC_MULTI_SUFFIXES = frozenset({
    "s3.amazonaws.com", "github.io", "gitlab.io", "herokuapp.com",
    "cloudfront.net", "azurewebsites.net", "appspot.com", "pages.dev",
})


def registrable_domain(host: str) -> str:
    """返回 host 的可注册域（eTLD+1）。

    >>> registrable_domain("crm.example.com.cn")
    'example.com.cn'
    >>> registrable_domain("idp.example.com.cn")
    'example.com.cn'
    >>> registrable_domain("www.example.com")
    'example.com'
    >>> registrable_domain("localhost")
    'localhost'
    """
    if not host:
        return ""
    host = host.strip().strip(".").lower()
    # 去掉端口（防御性：调用方通常已用 hostname 取值）
    if ":" in host:
        host = host.split(":", 1)[0]
    if not host:
        return ""
    parts = host.split(".")

    # IP 地址直接返回
    if all(p.isdigit() for p in parts) and len(parts) == 4:
        return host

    if len(parts) <= 2:
        return host

    tail2 = ".".join(parts[-2:])

    # 多段公共后缀（如 github.io、azurewebsites.net）：这类后缀本身就可注册，
    # 用户实际占用的是「后缀 + 一段」。故可注册域 = 末三段。
    if tail2 in _PUBLIC_MULTI_SUFFIXES:
        return ".".join(parts[-3:]) if len(parts) >= 3 else host

    # 末两段是常见 ccTLD 二级后缀（如 com.cn）→ 可注册域取末三段
    if tail2 in _SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])

    return tail2


def domain_matches(cookie_domain: str, host: str) -> bool:
    """RFC6265 域匹配：Cookie 域能否用于该主机。

    规则：
      * 具体域（不带前导点）须与主机完全相同；
      * 通配域（带前导点，如 .example.com）匹配该域及其任意子域；
      * 两边都归一化为小写、去前导点后比较。
    """
    if not cookie_domain or not host:
        return False

    cd = cookie_domain.strip().lower()
    h = host.strip().lower().split(":", 1)[0]

    if cd.startswith("."):
        base = cd.lstrip(".")
        return h == base or h.endswith("." + base)

    # 无前导点：按 RFC6265 视为 host-only，要求完全一致
    return h == cd


def same_site(cookie_domain: str, target_host: str) -> bool:
    """Cookie 是否属于目标站点（含其父域通配）。

    与 domain_matches 的区别：此处用**可注册域**做宽松判定，
    用于「这个 Cookie 是不是目标站的凭据」这类启发式判断。
    """
    if not cookie_domain or not target_host:
        return False
    a = registrable_domain(cookie_domain.lstrip("."))
    b = registrable_domain(target_host)
    return bool(a) and a == b
