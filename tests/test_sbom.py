# tests/test_sbom.py
from src.sbom import find_chain, _purl_matches, _short_name


def _sbom():
    def pkg(spdx, purl):
        return {"SPDXID": spdx, "name": spdx,
                "externalRefs": [{"referenceType": "purl", "referenceLocator": purl}]}
    return {
        "packages": [
            pkg("SPDXRef-Root", "pkg:github/org/repo@main"),
            pkg("SPDXRef-Parent", "pkg:maven/org.owasp/dependency-check-core@9.2.0"),
            pkg("SPDXRef-H2", "pkg:maven/com.h2database/h2@2.1.214"),
            pkg("SPDXRef-Lodash", "pkg:npm/lodash@4.17.20"),
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-Root",
             "relationshipType": "DESCRIBES"},
            {"spdxElementId": "SPDXRef-Root", "relatedSpdxElement": "SPDXRef-Parent",
             "relationshipType": "DEPENDS_ON"},
            {"spdxElementId": "SPDXRef-Parent", "relatedSpdxElement": "SPDXRef-H2",
             "relationshipType": "DEPENDS_ON"},
            {"spdxElementId": "SPDXRef-Root", "relatedSpdxElement": "SPDXRef-Lodash",
             "relationshipType": "DEPENDS_ON"},
        ],
    }


def test_find_chain_maven():
    chain = find_chain(_sbom(), "maven", "com.h2database:h2")
    assert chain == [
        "pkg:github/org/repo@main",
        "org.owasp:dependency-check-core@9.2.0",
        "com.h2database:h2@2.1.214",
    ]


def test_find_chain_direct_dep():
    chain = find_chain(_sbom(), "npm", "lodash")
    assert chain == ["pkg:github/org/repo@main", "pkg:npm/lodash@4.17.20"]


def test_find_chain_missing():
    assert find_chain(_sbom(), "maven", "no.such:lib") is None


def test_purl_matches():
    assert _purl_matches("pkg:maven/com.h2database/h2@2.1.214", "maven", "com.h2database:h2")
    assert _purl_matches("pkg:maven/com.h2database/h2@2.1.214", "maven", "h2")
    assert not _purl_matches("pkg:npm/lodash@4.17.20", "maven", "lodash")
    assert _purl_matches("pkg:npm/lodash@4.17.20", "npm", "lodash")
    assert _short_name("pkg:maven/com.h2database/h2@2.1.214?repository_url=x") == "com.h2database:h2@2.1.214"
