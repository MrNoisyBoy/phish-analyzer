"""Вспомогательные функции: домены, похожие домены, URL, обезвреживание IOC."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# Домены, которые чаще всего подделывают в атаках на клиентов российских финансовых организаций
PROTECTED_DOMAINS = [
    "sberbank.ru", "sber.ru", "vtb.ru", "tbank.ru", "tinkoff.ru", "alfabank.ru", "gazprombank.ru",
    "cbr.ru", "gosuslugi.ru", "nalog.gov.ru", "mos.ru", "pochta.ru", "fa.ru",
    "microsoft.com", "office.com", "apple.com", "google.com", "yandex.ru", "mail.ru",
]

GENERIC_BRANDS = {"mail", "office", "mos", "apple"}

URL_SHORTENERS ={"bit.ly", "tinyurl.com", "clck.ru", "goo.su", "t.co", "is.gd", "cutt.ly", "rb.gy", "u.to"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "work", "support", "rest", "su"}

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a",
                            # кириллица, визуально совпадающая с латиницей
                            "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "к": "k", "м": "m"})

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'()]+)""")


def domain_of(address: str) -> str:
    """Домен из e-mail адреса или URL, в нижнем регистре."""
    if "@" in address and "://" not in address:
        return address.rsplit("@", 1)[1].strip(" >").lower()
    if "://" not in address:
        address = "http://" + address
    host = urlparse(address).hostname or ""
    return host.lower().rstrip(".")


def registered_domain(host: str) -> str:
    """Упрощённое выделение регистрируемого домена: последние 2 метки (3 для *.gov.ru, *.com.ru и т.п.)."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"gov", "com", "org", "co", "net", "edu", "msk", "spb"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(host: str) -> str | None:
    """Вернуть защищаемый домен, под который маскируется host, или None.

    Ловит: опечатки (sberbsnk.ru), гомоглифы (vtb-0nline → vtb-online, кириллические буквы),
    rn→m, бренд в поддомене или через дефис (sberbank.ru.secure-login.top, sberbank-online.ru).
    """
    reg = registered_domain(host)
    if reg in PROTECTED_DOMAINS:
        return None
    norm_host = host.translate(HOMOGLYPHS).replace("rn", "m")
    norm_reg = registered_domain(norm_host)
    label = norm_reg.split(".")[0]
    for legit in PROTECTED_DOMAINS:
        brand = legit.split(".")[0]
        if norm_reg == legit:
            return legit  # совпадает после нормализации гомоглифов
        if brand in GENERIC_BRANDS:
            continue  # «mail», «office» встречаются в легитимных доменах повсюду
        # опечатка: только для длинных брендов, иначе uber.com ≈ sber.ru
        if len(brand) >= 6 and label != brand and levenshtein(label, brand) <= (1 if len(brand) < 8 else 2):
            return legit
        # бренд в поддомене или через дефис: sberbank.ru.secure.top, vtb-online.ru
        if len(brand) >= 3 and (legit in norm_host or re.search(rf"(^|[.\-]){re.escape(brand)}([.\-]|$)", norm_host)):
            return legit
    return None


def extract_urls(text: str) -> list[str]:
    urls = []
    for u in URL_RE.findall(text or ""):
        u = u.rstrip(".,;:!?»")
        urls.append(u if "://" in u else "http://" + u)
    return list(dict.fromkeys(urls))


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def defang(value: str) -> str:
    """Обезвредить IOC для безопасной пересылки в тикете/чате: hxxps[:]//evil[.]com"""
    return (value.replace("http://", "hxxp[:]//").replace("https://", "hxxps[:]//")
            .replace(".", "[.]").replace("@", "[@]"))
