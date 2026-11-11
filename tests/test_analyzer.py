from email.message import EmailMessage

import pytest

from phishanalyzer.analyzer import analyze_message
from phishanalyzer.indicators import defang, domain_of, extract_urls, lookalike_of, registered_domain
from phishanalyzer.samples import SAMPLES


def codes(report):
    return {f.code for f in report.findings}


def msg(frm="Отдел кадров <hr@company.example>", subject="Привет", body="Текст", html=None, auth=None, **headers):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, "me@company.example", subject
    if auth:
        m["Authentication-Results"] = f"mx; {auth}"
    for k, v in headers.items():
        m[k.replace("_", "-")] = v
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    return m


# ---------- индикаторы ----------

@pytest.mark.parametrize("host,expected", [
    ("sberbank-0nline.ru", "sberbank.ru"),          # бренд через дефис + гомоглиф
    ("sberbank.ru.verify.top", "sberbank.ru"),      # бренд в поддомене
    ("gosusluqi.ru", "gosuslugi.ru"),               # опечатка
    ("vtb.ru.login-check.xyz", "vtb.ru"),
    ("rnail.ru", "mail.ru"),                        # rn → m
    ("nalog-gov.ru", "nalog.gov.ru"),
    ("ѕberbank.ru".replace("ѕ", "s").replace("e", "е"), "sberbank.ru"),  # кириллическая «е»
])
def test_lookalike_detected(host, expected):
    assert lookalike_of(host) == expected


@pytest.mark.parametrize("host", ["sberbank.ru", "online.sberbank.ru", "nalog.gov.ru", "gmail.com",
                                  "uber.com", "mail.company.ru", "office.example.com", "github.com"])
def test_lookalike_no_false_positive(host):
    assert lookalike_of(host) is None


def test_helpers():
    assert domain_of("User <a@Sub.Example.COM>".split("<")[1]) == "sub.example.com"
    assert registered_domain("lk.nalog.gov.ru") == "nalog.gov.ru"
    assert extract_urls("см. https://a.example/x, и www.b.example.") == ["https://a.example/x", "http://www.b.example"]
    assert defang("https://evil.example/a@b") == "hxxps[:]//evil[.]example/a[@]b"


# ---------- анализ писем ----------

def test_clean_mail_is_clean():
    r = analyze_message(msg(auth="spf=pass; dkim=pass; dmarc=pass"))
    assert r.verdict == "clean" and r.findings == []


def test_auth_failures():
    r = analyze_message(msg(auth="spf=fail; dkim=none; dmarc=fail"))
    assert {"AUTH-SPF", "AUTH-DKIM", "AUTH-DMARC"} <= codes(r)


def test_link_text_mismatch():
    html = '<a href="http://203.0.113.9/login">https://online.sberbank.ru</a>'
    r = analyze_message(msg(html=html))
    assert {"URL-MISMATCH", "URL-IP"} <= codes(r)


def test_url_with_at_sign_masks_host():
    r = analyze_message(msg(body="Вход: https://sberbank.ru@203.0.113.9/login"))
    assert "URL-AT" in codes(r)


def test_double_extension_attachment():
    m = msg()
    m.add_attachment(b"x", maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
    m.add_attachment(b"y", maintype="application", subtype="octet-stream", filename="report.docm")
    r = analyze_message(m)
    assert {"ATT-DOUBLE", "ATT-MACRO"} <= codes(r)
    assert r.attachments[0].sha256 == "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"


def test_display_name_with_other_address():
    r = analyze_message(msg(frm='"security@sberbank.ru" <alert@evil.example>'))
    assert "SND-DISPLAY" in codes(r)


def test_reply_to_mismatch():
    r = analyze_message(msg(Reply_To="other@another.example"))
    assert "SND-REPLYTO" in codes(r)


def test_repeated_finding_counted_once():
    body = " ".join(f"https://bit.ly/{i}" for i in range(5))
    r = analyze_message(msg(body=body))
    short = [f for f in r.findings if f.code == "URL-SHORT"]
    assert len(short) == 1 and short[0].weight == 10 and "bit.ly/4" in short[0].detail


@pytest.mark.parametrize("name,verdict", [
    ("01_legit_bank_notice.eml", "clean"),
    ("02_phish_bank_lookalike.eml", "phishing"),
    ("03_malware_tax_notice.eml", "phishing"),
    ("04_bec_ceo_fraud.eml", "suspicious"),
])
def test_sample_verdicts(name, verdict):
    assert analyze_message(SAMPLES[name]()).verdict == verdict


def test_iocs_exclude_official_domains():
    r = analyze_message(SAMPLES["02_phish_bank_lookalike.eml"]())
    ioc = r.iocs()
    assert not any("online.sberbank.ru" in u for u in ioc["urls"])
    assert "sberbank-0nline.ru" in ioc["domains"] and "sberbank.ru" not in ioc["domains"]


def test_freemail_domains_not_in_iocs():
    ioc = analyze_message(SAMPLES["04_bec_ceo_fraud.eml"]()).iocs()
    assert "gmail.com" not in ioc["domains"]
    assert "petrov.ceo.office@gmail.com" in ioc["emails"]
