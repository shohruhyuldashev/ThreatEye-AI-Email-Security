from services.roster import parse_targets
from framework.learning import apply_reputation, _domain, _url_domain
from tests.conftest import FakeCursor


def test_parse_headered_csv():
    csv = "email,first_name,last_name,department,position\njohn.doe@corp.com,John,Doe,Finance,Analyst\njane@corp.com,Jane,Smith,Sales,Rep\n"
    r = parse_targets(csv)
    assert len(r) == 2
    j = next(x for x in r if x["email"] == "john.doe@corp.com")
    assert j["first_name"] == "John" and j["department"] == "Finance"


def test_parse_alias_headers_semicolon_and_fullname():
    csv = "Mail;Name;Dept\nalice@corp.com;Alice Wonder;Engineering\nbob@corp.com;Bob;HR\n"
    r = parse_targets(csv)
    a = next(x for x in r if x["email"] == "alice@corp.com")
    assert a["first_name"] == "Alice" and a["last_name"] == "Wonder" and a["department"] == "Engineering"


def test_parse_plain_email_list():
    txt = "ceo@corp.com\nfinance@corp.com\ngarbage line\nsupport@corp.com"
    r = parse_targets(txt)
    assert sorted(x["email"] for x in r) == ["ceo@corp.com", "finance@corp.com", "support@corp.com"]
    assert all(x["department"] == "General" for x in r)


def test_parse_dedup():
    r = parse_targets("email,department\nx@corp.com,Finance\nx@corp.com,Sales\n")
    assert len(r) == 1


def test_reputation_learned_bad():
    store = [{"organization_id": 1, "kind": "sender_domain", "value": "evil.com", "score": 80}]
    r = apply_reputation(1, "attacker@evil.com", [], FakeCursor(store))
    assert r["delta"] == 25 and "known-bad" in r["verdict"]


def test_reputation_learned_trusted():
    store = [{"organization_id": 1, "kind": "sender_addr", "value": "ceo@trusted.com", "score": -70}]
    r = apply_reputation(1, "ceo@trusted.com", [], FakeCursor(store))
    assert r["delta"] == -25 and "trusted" in r["verdict"]


def test_reputation_neutral():
    r = apply_reputation(1, "x@neutral.com", [], FakeCursor([]))
    assert r["delta"] == 0


def test_domain_helpers():
    assert _domain("a.b@Mail.Evil.CO.UK") == "evil.co.uk"
    assert _url_domain("http://login.evil.com/x") == "evil.com"
