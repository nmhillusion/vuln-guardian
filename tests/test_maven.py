# tests/test_maven.py
from unittest.mock import MagicMock, patch
from src.maven import get_latest_version, parse_maven_parent

_XML = """<metadata><groupId>org.owasp</groupId><artifactId>dependency-check-gradle</artifactId>
<versioning><latest>9.3.0</latest><release>9.3.0</release>
<versions><version>9.2.0</version><version>9.3.0</version></versions>
<lastUpdated>20260101000000</lastUpdated></versioning></metadata>"""

_XML_NO_LATEST = """<metadata><versioning>
<versions><version>1.0</version><version>2.0</version></versions>
</versioning></metadata>"""


def _resp(text):
    r = MagicMock()
    r.text = text
    return r


def test_get_latest_version():
    with patch("src.maven.httpx.get", return_value=_resp(_XML)):
        assert get_latest_version("org.owasp", "dependency-check-gradle") == "9.3.0"


def test_get_latest_version_falls_back_to_last_listed():
    with patch("src.maven.httpx.get", return_value=_resp(_XML_NO_LATEST)):
        assert get_latest_version("g", "a") == "2.0"


def test_get_latest_version_network_failure():
    with patch("src.maven.httpx.get", side_effect=Exception("boom")):
        assert get_latest_version("g", "a") is None


def test_parse_maven_parent():
    assert parse_maven_parent("org.owasp:dependency-check-core@9.2.0") == ("org.owasp", "dependency-check-core")
    assert parse_maven_parent("pkg:github/o/r@main") is None
    assert parse_maven_parent("lodash") is None
