"""Анализ e-mail (.eml) на признаки фишинга.

Анализ полностью офлайн: письмо не открывается в почтовом клиенте, ссылки не посещаются,
вложения не запускаются — только разбор структуры и подсчёт хешей.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path

from .indicators import (PROTECTED_DOMAINS, SUSPICIOUS_TLDS, URL_SHORTENERS, domain_of, extract_urls, is_ip, lookalike_of,
                         registered_domain)

DANGEROUS_EXT = {".exe", ".scr", ".com", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1",
                 ".lnk", ".iso", ".img", ".vhd", ".msi", ".jar", ".cpl", ".chm", ".svg", ".html", ".htm"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".cab", ".ace"}

URGENCY = [r"срочно", r"немедленно", r"в течение \d+ (час|дн|сут)", r"заблокир", r"приостановлен", r"последнее предупреждение",
           r"подтвердите", r"обновите данные", r"подозрительн\w* (операци|вход|активност)", r"штраф",
           r"urgent", r"immediately", r"suspended", r"verify your", r"within \d+ hours", r"account (will be )?locked"]
CREDENTIALS = [r"парол", r"код из смс", r"cvv|cvc", r"номер карты", r"логин", r"войдите", r"личн\w+ кабинет",
               r"password", r"sign in", r"log ?in", r"credentials"]

PAYMENT = [r"оплат", r"реквизит", r"перевод\w* (средств|денег)", r"сч[её]т на оплату", r"wire transfer", r"invoice payment"]
FREEMAIL = {"gmail.com", "mail.ru", "yandex.ru", "ya.ru", "bk.ru", "inbox.ru", "list.ru", "rambler.ru", "outlook.com",
            "hotmail.com", "yahoo.com", "proton.me", "protonmail.com", "icloud.com"}
EXEC_TITLES = re.compile(r"директор|руководител|бухгалтер|финансов|ceo|cfo|director|president", re.I)

VERDICTS = [(60, "phishing"), (30, "suspicious"), (0, "clean")]


@dataclass
class Finding:
    code: str
    title: str
    weight: int
    detail: str


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str


@dataclass
class Report:
    subject: str
    from_addr: str
    from_name: str
    reply_to: str
    return_path: str
    date: str
    auth: dict
    received_ips: list[str]
    urls: list[str]
    attachments: list[Attachment]
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(f.weight for f in self.findings))

    @property
    def verdict(self) -> str:
        return next(v for threshold, v in VERDICTS if self.score >= threshold)

    def iocs(self) -> dict[str, list[str]]:
        """Индикаторы компрометации. Официальные домены брендов исключаются — их нельзя блокировать."""
        legit = lambda d: registered_domain(d) in PROTECTED_DOMAINS
        urls = [u for u in self.urls if not legit(domain_of(u))]
        senders = [a for a in (self.from_addr, self.reply_to) if a]
        domains = {domain_of(u) for u in urls} | {domain_of(a) for a in senders}
        # общедоступные почтовые сервисы блокировать нельзя — для них IOC это конкретный адрес
        domains = sorted(d for d in domains if d and not legit(d) and d not in FREEMAIL)
        return {"urls": urls, "domains": domains, "emails": senders, "ips": self.received_ips,
                "sha256": [a.sha256 for a in self.attachments]}


class _LinkParser(HTMLParser):
    """Собирает пары (href, видимый текст) из HTML-тела письма."""

    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []
        self.text_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href", "")
            self._text = []

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None

    def handle_data(self, data):
        self.text_parts.append(data)
        if self._href is not None:
            self._text.append(data)


def _parse_auth_results(msg: EmailMessage) -> dict:
    auth = {}
    for header in msg.get_all("Authentication-Results", []):
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}=(\w+)", str(header), re.I)
            if m and mech not in auth:
                auth[mech] = m[1].lower()
    if "spf" not in auth and (rs := msg.get("Received-SPF")):
        auth["spf"] = str(rs).split()[0].lower()
    return auth


def _received_ips(msg: EmailMessage) -> list[str]:
    ips = []
    for h in msg.get_all("Received", []):
        for ip in re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", str(h)):
            if not ip.startswith(("10.", "127.", "192.168.")) and ip not in ips:
                ips.append(ip)
    return ips


def _body(msg: EmailMessage) -> tuple[str, list[tuple[str, str]]]:
    """Текст письма и ссылки из HTML."""
    text_parts, links = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            content = part.get_payload(decode=True).decode("utf-8", "replace")
        if ctype == "text/html":
            p = _LinkParser()
            p.feed(content)
            links += p.links
            text_parts.append(" ".join(p.text_parts))
        else:
            text_parts.append(content)
    return "\n".join(text_parts), links


def _attachments(msg: EmailMessage) -> list[Attachment]:
    result = []
    for part in msg.iter_attachments():
        data = part.get_payload(decode=True) or b""
        result.append(Attachment(filename=part.get_filename() or "(без имени)", content_type=part.get_content_type(),
                                 size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                 md5=hashlib.md5(data).hexdigest()))
    return result


def analyze_message(msg: EmailMessage) -> Report:
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_to = getaddresses([str(msg.get("Reply-To", ""))])[0][1] if msg.get("Reply-To") else ""
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    text, html_links = _body(msg)
    urls = list(dict.fromkeys([h for h, _ in html_links if h.lower().startswith(("http", "www"))] + extract_urls(text)))

    r = Report(subject=str(msg.get("Subject", "")), from_addr=from_addr.lower(), from_name=from_name,
               reply_to=reply_to.lower(), return_path=return_path.lower(), date=str(msg.get("Date", "")),
               auth=_parse_auth_results(msg), received_ips=_received_ips(msg), urls=urls,
               attachments=_attachments(msg))
    add = lambda code, title, w, detail: r.findings.append(Finding(code, title, w, detail))
    from_dom = domain_of(r.from_addr) if r.from_addr else ""

    # --- аутентификация отправителя ---
    if r.auth.get("spf") in ("fail", "softfail"):
        add("AUTH-SPF", "SPF не пройден", 20 if r.auth["spf"] == "fail" else 10, f"spf={r.auth['spf']}")
    if r.auth.get("dkim") in ("fail", "none", "neutral"):
        add("AUTH-DKIM", "Нет валидной DKIM-подписи", 10, f"dkim={r.auth['dkim']}")
    if r.auth.get("dmarc") == "fail":
        add("AUTH-DMARC", "DMARC не пройден", 25, "dmarc=fail — домен отправителя, вероятно, подделан")
    if not r.auth:
        add("AUTH-NONE", "Нет результатов проверки SPF/DKIM/DMARC", 5, "заголовок Authentication-Results отсутствует")

    # --- отправитель ---
    if from_dom and (legit := lookalike_of(from_dom)):
        add("SND-LOOKALIKE", "Домен отправителя имитирует известный", 35, f"{from_dom} ≈ {legit}")
    if from_dom.startswith("xn--") or ".xn--" in from_dom:
        add("SND-PUNY", "Punycode в домене отправителя", 15, from_dom)
    if r.reply_to and registered_domain(domain_of(r.reply_to)) != registered_domain(from_dom):
        add("SND-REPLYTO", "Reply-To ведёт на другой домен", 15, f"From: {from_dom}, Reply-To: {domain_of(r.reply_to)}")
    if r.return_path and registered_domain(domain_of(r.return_path)) != registered_domain(from_dom):
        add("SND-RETPATH", "Return-Path не совпадает с From", 5, f"Return-Path: {domain_of(r.return_path)}")
    if from_name and from_dom in FREEMAIL and EXEC_TITLES.search(from_name):
        add("SND-FREEMAIL-EXEC", "Руководитель пишет с бесплатной почты (признак BEC)", 20, f"«{from_name}» <{r.from_addr}>")
    if from_name:
        name_emails = re.findall(r"[\w.+-]+@[\w.-]+", from_name)
        if name_emails and domain_of(name_emails[0]) != from_dom:
            add("SND-DISPLAY", "В имени отправителя указан другой адрес", 20, f"«{from_name}» <{r.from_addr}>")
        elif (brand := lookalike_brand_in_name(from_name)) and registered_domain(from_dom) not in brand:
            add("SND-BRAND", "Имя отправителя использует бренд, домен — чужой", 20, f"«{from_name}» <{r.from_addr}>")

    # --- ссылки ---
    for href, label in html_links:
        label_urls = extract_urls(label) or ([label] if re.match(r"^[\w-]+(\.[\w-]+)+(/\S*)?$", label) else [])
        if label_urls and href.lower().startswith("http"):
            if registered_domain(domain_of(label_urls[0])) != registered_domain(domain_of(href)):
                add("URL-MISMATCH", "Текст ссылки не совпадает с адресом", 25, f"показано {label} → ведёт на {href}")
    for u in r.urls:
        host = domain_of(u)
        if is_ip(host):
            add("URL-IP", "Ссылка на IP-адрес вместо домена", 20, u)
        if host in URL_SHORTENERS:
            add("URL-SHORT", "Сокращённая ссылка скрывает адрес", 10, u)
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            add("URL-TLD", "Подозрительная доменная зона", 10, u)
        if "xn--" in host:
            add("URL-PUNY", "Punycode-домен в ссылке", 15, u)
        if "@" in u.split("://", 1)[-1].split("/", 1)[0]:
            add("URL-AT", "Символ @ в адресе ссылки (маскировка хоста)", 20, u)
        if (legit := lookalike_of(host)):
            add("URL-LOOKALIKE", "Ссылка на домен-двойник", 35, f"{host} ≈ {legit}")

    # --- текст ---
    low = f"{r.subject}\n{text}".lower()
    urgency = sorted({m.group(0) for p in URGENCY for m in [re.search(p, low)] if m})
    creds = sorted({m.group(0) for p in CREDENTIALS for m in [re.search(p, low)] if m})
    if urgency:
        add("TXT-URGENCY", "Давление срочностью или угрозой", 10, ", ".join(urgency))
    payment = sorted({m.group(0) for p in PAYMENT for m in [re.search(p, low)] if m})
    if payment:
        add("TXT-PAYMENT", "Просьба об оплате или смене реквизитов", 10, ", ".join(payment))
    if creds and r.urls:
        add("TXT-CREDS", "Просьба ввести учётные данные по ссылке", 15, ", ".join(creds))

    # --- вложения ---
    for a in r.attachments:
        name = a.filename.lower()
        suffixes = re.findall(r"\.[a-z0-9]{1,5}", name)
        ext = suffixes[-1] if suffixes else ""
        if len(suffixes) >= 2 and ext in DANGEROUS_EXT:
            add("ATT-DOUBLE", "Двойное расширение у вложения", 40, a.filename)
        elif ext in DANGEROUS_EXT:
            add("ATT-EXEC", "Исполняемое или опасное вложение", 35, a.filename)
        if ext in MACRO_EXT:
            add("ATT-MACRO", "Документ с макросами", 25, a.filename)
        if ext in ARCHIVE_EXT:
            add("ATT-ARCHIVE", "Архив во вложении", 10, a.filename)

    # одинаковые находки по разным ссылкам не должны раздувать скор: вес учитываем один раз, детали объединяем
    merged: dict[str, Finding] = {}
    for f in r.findings:
        if f.code in merged:
            if f.detail not in merged[f.code].detail:
                merged[f.code].detail += "; " + f.detail
        else:
            merged[f.code] = f
    r.findings = sorted(merged.values(), key=lambda f: -f.weight)
    return r


def lookalike_brand_in_name(name: str) -> str | None:
    """Если в отображаемом имени упомянут известный бренд — вернуть его домен(ы)."""
    brands = {"сбер": "sberbank.ru sber.ru", "sber": "sberbank.ru sber.ru", "втб": "vtb.ru", "vtb": "vtb.ru",
              "т-банк": "tbank.ru tinkoff.ru", "тинькофф": "tbank.ru tinkoff.ru", "альфа": "alfabank.ru",
              "госуслуг": "gosuslugi.ru", "фнс": "nalog.gov.ru", "налогов": "nalog.gov.ru",
              "центральный банк": "cbr.ru", "банк россии": "cbr.ru", "microsoft": "microsoft.com office.com"}
    low = name.lower()
    return next((dom for key, dom in brands.items() if key in low), None)


def analyze_file(path: Path | str) -> Report:
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return analyze_message(msg)
