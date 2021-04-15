import pytest
import requests_mock

from pubtools._quay import manifest_list_merger, quay_client

old_ml = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
    "manifests": [
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:1111111111",
            "platform": {"architecture": "arm64", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:2222222222",
            "platform": {"architecture": "armhfp", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:3333333333",
            "platform": {"architecture": "ppc64le", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:5555555555",
            "platform": {"architecture": "amd64", "os": "linux"},
        },
    ],
}

new_ml = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
    "manifests": [
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:6666666666",
            "platform": {"architecture": "arm64", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:7777777777",
            "platform": {"architecture": "ppc64le", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:8888888888",
            "platform": {"architecture": "s390x", "os": "linux"},
        },
    ],
}

merged_ml = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
    "manifests": [
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:6666666666",
            "platform": {"architecture": "arm64", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:2222222222",
            "platform": {"architecture": "armhfp", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:7777777777",
            "platform": {"architecture": "ppc64le", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:8888888888",
            "platform": {"architecture": "s390x", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:5555555555",
            "platform": {"architecture": "amd64", "os": "linux"},
        },
    ],
}

expected_missing_archs = [
    {
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "size": 429,
        "digest": "sha256:2222222222",
        "platform": {"architecture": "armhfp", "os": "linux"},
    },
    {
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "size": 429,
        "digest": "sha256:5555555555",
        "platform": {"architecture": "amd64", "os": "linux"},
    },
]


def test_init():
    merger = manifest_list_merger.ManifestListMerger("quay.io/src/image:1", "quay.io/dest/image:1")
    assert merger.src_image == "quay.io/src/image:1"
    assert merger.dest_image == "quay.io/dest/image:1"
    assert merger._quay_client is None


def test_init_create_client():
    merger = manifest_list_merger.ManifestListMerger(
        "quay.io/src/image:1",
        "quay.io/dest/image:1",
        "user",
        "pass",
        host="stage.quay.io",
    )
    assert merger.src_image == "quay.io/src/image:1"
    assert merger.dest_image == "quay.io/dest/image:1"
    assert isinstance(merger._quay_client, quay_client.QuayClient)
    assert merger._quay_client.username == "user"
    assert merger._quay_client.password == "pass"
    assert merger._quay_client.session.hostname == "stage.quay.io"


def test_set_client():
    merger = manifest_list_merger.ManifestListMerger("quay.io/src/image:1", "quay.io/dest/image:1")
    assert merger.src_image == "quay.io/src/image:1"
    assert merger.dest_image == "quay.io/dest/image:1"
    assert merger._quay_client is None

    client = quay_client.QuayClient("user", "pass")
    merger.set_quay_client(client)
    assert client == merger._quay_client


def test_get_missing_architectures():
    merger = manifest_list_merger.ManifestListMerger("quay.io/src/image:1", "quay.io/dest/image:1")
    missing = merger.get_missing_architectures(new_ml, old_ml)

    assert missing == expected_missing_archs


def test_add_missing_architectures():
    merger = manifest_list_merger.ManifestListMerger("quay.io/src/image:1", "quay.io/dest/image:1")
    merged_manifest_list = merger._add_missing_architectures(new_ml, expected_missing_archs)

    merged_manifest_list["manifests"].sort(key=lambda manifest: manifest["digest"])
    merged_ml["manifests"].sort(key=lambda manifest: manifest["digest"])
    assert merged_manifest_list == merged_ml


def test_merge_manifest_lists_success():
    merger = manifest_list_merger.ManifestListMerger(
        "quay.io/src/image:1", "quay.io/dest/image:1", "user", "pass"
    )

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/src/image/manifests/1",
            json=new_ml,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/dest/image/manifests/1",
            json=old_ml,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.put("https://quay.io/v2/dest/image/manifests/1", status_code=200)

        merger.merge_manifest_lists()
        assert m.call_count == 3
        sent_ml = m.request_history[-1].json()
        sent_ml["manifests"].sort(key=lambda manifest: manifest["digest"])
        merged_ml["manifests"].sort(key=lambda manifest: manifest["digest"])

        assert sent_ml == merged_ml


def test_merge_manifest_lists_missing_client():
    merger = manifest_list_merger.ManifestListMerger("quay.io/src/image:1", "quay.io/dest/image:1")

    with pytest.raises(RuntimeError, match="QuayClient instance must be set"):
        merger.merge_manifest_lists()
