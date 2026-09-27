# tests/test_maven.py
from unittest.mock import MagicMock, patch
from src.maven import get_latest_version, is_stable_version, parse_maven_parent, version_exists_on_central

_XML = """<metadata><groupId>org.owasp</groupId><artifactId>dependency-check-gradle</artifactId>
<versioning><latest>9.3.0</latest><release>9.3.0</release>
<versions><version>9.2.0</version><version>9.3.0</version></versions>
<lastUpdated>20260101000000</lastUpdated></versioning></metadata>"""

_XML_NO_LATEST = """<metadata><versioning>
<versions><version>1.0</version><version>2.0</version></versions>
</versioning></metadata>"""

_XML_MILESTONE_LATEST = """<metadata><groupId>org.springframework</groupId><artifactId>spring-jdbc</artifactId>
<versioning><latest>7.1.0-M2</latest><release>7.1.0-M2</release>
<versions><version>6.2.14</version><version>6.2.19</version><version>7.0.9</version><version>7.1.0-M1</version><version>7.1.0-M2</version></versions>
<lastUpdated>20260924062821</lastUpdated></versioning></metadata>"""

_XML_ALL_PRERELEASE = """<metadata><versioning><latest>2.0-beta</latest>
<versions><version>2.0-alpha1</version><version>2.0-beta</version></versions>
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


def test_get_latest_version_skips_milestone_latest():
    with patch("src.maven.httpx.get", return_value=_resp(_XML_MILESTONE_LATEST)):
        assert get_latest_version("org.springframework", "spring-jdbc") == "7.0.9"


def test_get_latest_version_all_prerelease_returns_none():
    with patch("src.maven.httpx.get", return_value=_resp(_XML_ALL_PRERELEASE)):
        assert get_latest_version("g", "a") is None


def test_is_stable_version():
    for v in ("6.2.19", "7.0.9", "9.3.0", "5.3.39", "2.0", "3.0.0.RELEASE", "2.5.6.SEC01"):
        assert is_stable_version(v), v
    for v in (
        "7.1.0-M2", "7.0.0-M1", "7.0.0-RC1", "5.7-alpha1", "1.0-beta",
        "2.0-SNAPSHOT", "1.2-rc1", "1.0-m4", "1.0-preview", "1.0-eap",
    ):
        assert not is_stable_version(v), v


def test_parse_maven_parent():
    assert parse_maven_parent("org.owasp:dependency-check-core@9.2.0") == ("org.owasp", "dependency-check-core")
    assert parse_maven_parent("pkg:github/o/r@main") is None
    assert parse_maven_parent("lodash") is None


_XML_BOOT_VERSIONS = """<metadata><versioning><latest>3.4.13</latest><release>3.4.13</release>
<versions><version>3.4.5</version><version>3.4.13</version></versions>
</versioning></metadata>"""


def test_version_exists_on_central_true():
    with patch("src.maven.httpx.get", return_value=_resp(_XML_BOOT_VERSIONS)):
        assert version_exists_on_central(
            "org.springframework.boot", "spring-boot-autoconfigure", "3.4.13"
        ) is True


def test_version_exists_on_central_false_for_hallucinated_version():
    with patch("src.maven.httpx.get", return_value=_resp(_XML_BOOT_VERSIONS)):
        assert version_exists_on_central(
            "org.springframework.boot", "spring-boot-autoconfigure", "3.4.17"
        ) is False


def test_version_exists_on_central_network_failure_returns_none():
    with patch("src.maven.httpx.get", side_effect=Exception("boom")):
        assert version_exists_on_central("g", "a", "1.0") is None
