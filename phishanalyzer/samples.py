"""Создание демонстрационных писем (.eml).

Все домены-двойники вымышлены, IP-адреса — из документационных диапазонов RFC 5737.
Вложение «.pdf.exe» — безобидная заглушка из текста, а не исполняемый файл.
"""
from __future__ import annotations

import argparse
import hashlib
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timezone
from pathlib import Path

DATE = format_datetime(datetime(2026, 11, 10, 9, 41, tzinfo=timezone.utc))


def _base(frm: str, subject: str, auth: str, received_ip: str, **extra) -> EmailMessage:
    m = EmailMessage()
    m["Received"] = f"from mx.example-mail.net ([{received_ip}]) by mx.fa-corp.example with ESMTPS; {DATE}"
    m["Authentication-Results"] = f"mx.fa-corp.example; {auth}"
    m["From"] = frm
    m["To"] = "k.rusakov@fa-corp.example"
    m["Subject"] = subject
    m["Date"] = DATE
    m["Message-ID"] = f"<{hashlib.md5(subject.encode()).hexdigest()[:12]}@{frm.split('@')[-1].rstrip('>')}>"
    for k, v in extra.items():
        m[k.replace("_", "-")] = v
    return m


def legit_bank_notice() -> EmailMessage:
    m = _base("СберБанк <noreply@sberbank.ru>", "Выписка по счёту за октябрь",
              "spf=pass smtp.mailfrom=sberbank.ru; dkim=pass header.d=sberbank.ru; dmarc=pass", "192.0.2.10",
              Return_Path="<bounce@sberbank.ru>")
    m.set_content("Здравствуйте!\nВыписка за октябрь доступна в СберБанк Онлайн: https://online.sberbank.ru/statements\n")
    m.add_alternative("""<p>Здравствуйте!</p><p>Выписка за октябрь доступна в
<a href="https://online.sberbank.ru/statements">СберБанк Онлайн</a>.</p>""", subtype="html")
    return m


def phish_bank_lookalike() -> EmailMessage:
    m = _base("СберБанк Онлайн <security@sberbank-0nline.ru>", "Ваша карта заблокирована — подтвердите данные",
              "spf=softfail smtp.mailfrom=sberbank-0nline.ru; dkim=none; dmarc=fail header.from=sberbank-0nline.ru",
              "203.0.113.200", Reply_To="support@helpdesk-bank.top", Return_Path="<mailer@bulk-sender.xyz>")
    m.set_content("Уважаемый клиент! Зафиксирована подозрительная операция. Карта заблокирована.\n"
                  "Подтвердите данные в течение 24 часов: http://sberbank-0nline.ru.verify-account.top/login")
    m.add_alternative("""<p>Уважаемый клиент!</p>
<p>Зафиксирована <b>подозрительная операция</b> по вашей карте. Карта временно заблокирована.</p>
<p>Чтобы избежать списания, <b>срочно</b> подтвердите данные в течение 24 часов — войдите в личный кабинет:</p>
<p><a href="http://sberbank-0nline.ru.verify-account.top/login">https://online.sberbank.ru/login</a></p>
<p>Если ссылка не открывается: <a href="https://bit.ly/3xAmPle">bit.ly/3xAmPle</a></p>
<p>Потребуются номер карты, CVV и код из СМС.</p>""", subtype="html")
    return m


def malware_tax_notice() -> EmailMessage:
    m = _base("ФНС России <info@nalog-gov.ru>", "Требование об уплате налога № 4417",
              "spf=fail smtp.mailfrom=nalog-gov.ru; dkim=none; dmarc=none", "198.51.100.77")
    m.set_content("Направляем требование об уплате задолженности. Во избежание штрафа оплатите в течение 3 дней.\n"
                  "Требование и реквизиты во вложении.")
    m.add_attachment(b"DEMO PLACEHOLDER - not an executable", maintype="application",
                     subtype="octet-stream", filename="Требование_об_уплате.pdf.exe")
    m.add_attachment(b"PK\x03\x04 demo archive placeholder", maintype="application", subtype="zip",
                     filename="Акт_сверки.zip")
    return m


def bec_ceo_fraud() -> EmailMessage:
    m = _base("Петров Андрей (Генеральный директор) <petrov.ceo.office@gmail.com>", "Срочно: оплата поставщику",
              "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass", "192.0.2.55",
              Reply_To="a.petrov.director@proton.me")
    m.set_content("Добрый день.\nСрочно нужно оплатить счёт новому поставщику до 15:00, реквизиты пришлю отдельно. "
                  "Я на совещании, не звоните — отвечайте сюда.\nА. Петров")
    return m


SAMPLES = {
    "01_legit_bank_notice.eml": legit_bank_notice,
    "02_phish_bank_lookalike.eml": phish_bank_lookalike,
    "03_malware_tax_notice.eml": malware_tax_notice,
    "04_bec_ceo_fraud.eml": bec_ceo_fraud,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Создать демонстрационные письма")
    parser.add_argument("-o", "--out-dir", default="samples")
    args = parser.parse_args()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, make in SAMPLES.items():
        (out / name).write_bytes(bytes(make()))
    print(f"Создано {len(SAMPLES)} писем в {out}/")


if __name__ == "__main__":
    main()
