from copy import deepcopy

import mock
import pytest
import requests
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

merged_ml2 = {
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
            "digest": "sha256:3333333333",
            "platform": {"architecture": "ppc64le", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:5555555555",
            "platform": {"architecture": "amd64", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 429,
            "digest": "sha256:8888888888",
            "platform": {"architecture": "s390x", "os": "linux"},
        },
    ],
}

merged_ml3 = {
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
            "digest": "sha256:8888888888",
            "platform": {"architecture": "s390x", "os": "linux"},
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
    assert merger._src_quay_client is None
    assert merger._dest_quay_client is None


def test_init_create_client():
    merger = manifest_list_merger.ManifestListMerger(
        "quay.io/src/image:1",
        "quay.io/dest/image:1",
        "src.quay.io",
        "src-user",
        "src-pass",
        "dest-user",
        "dest-pass",
        host="stage.quay.io",
    )
    assert merger.src_image == "quay.io/src/image:1"
    assert merger.dest_image == "quay.io/dest/image:1"
    assert isinstance(merger._src_quay_client, quay_client.QuayClient)
    assert isinstance(merger._dest_quay_client, quay_client.QuayClient)
    assert merger._src_quay_client.username == "src-user"
    assert merger._src_quay_client.password == "src-pass"
    assert merger._src_quay_client.session.hostname == "src.quay.io"
    assert merger._dest_quay_client.username == "dest-user"
    assert merger._dest_quay_client.password == "dest-pass"
    assert merger._dest_quay_client.session.hostname == "stage.quay.io"


def test_set_client():
    merger = manifest_list_merger.ManifestListMerger("quay.io/src/image:1", "quay.io/dest/image:1")
    assert merger.src_image == "quay.io/src/image:1"
    assert merger.dest_image == "quay.io/dest/image:1"
    assert merger._src_quay_client is None
    assert merger._dest_quay_client is None

    src_client = quay_client.QuayClient("src-user", "src-pass")
    dest_client = quay_client.QuayClient("dest-user", "dest-pass")
    merger.set_quay_clients(src_client, dest_client)
    assert src_client == merger._src_quay_client
    assert dest_client == merger._dest_quay_client


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
        "quay.io/src/image:1",
        "quay.io/dest/image:1",
        "src-quay.io",
        "src-user",
        "src-pass",
        "dest-user",
        "dest-pass",
    )

    with requests_mock.Mocker() as m:
        m.get(
            "https://src-quay.io/v2/src/image/manifests/1",
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
        expected_ml = deepcopy(merged_ml)
        expected_ml["manifests"].sort(key=lambda manifest: manifest["digest"])

        assert sent_ml == expected_ml


def test_merge_manifest_lists_missing_client():
    merger = manifest_list_merger.ManifestListMerger("quay.io/src/image:1", "quay.io/dest/image:1")

    with pytest.raises(RuntimeError, match="QuayClient instance must be set"):
        merger.merge_manifest_lists()


def test_merge_selected_architectures():
    merger = manifest_list_merger.ManifestListMerger(
        "quay.io/src/image:1",
        "quay.io/dest/image:1",
        "src-quay.io",
        "src-user",
        "src-pass",
        "dest-user",
        "dest-pass",
    )

    with requests_mock.Mocker() as m:
        m.get(
            "https://src-quay.io/v2/src/image/manifests/1",
            json=new_ml,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/dest/image/manifests/1",
            json=old_ml,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

        created_ml = merger.merge_manifest_lists_selected_architectures(["arm64", "s390x"])
        assert m.call_count == 2
        created_ml["manifests"].sort(key=lambda manifest: manifest["digest"])
        expected_ml = deepcopy(merged_ml2)
        expected_ml["manifests"].sort(key=lambda manifest: manifest["digest"])

        assert created_ml == expected_ml


@mock.patch("pubtools._quay.quay_client.QuayClient._authenticate_quay")
def test_merge_selected_architectures_no_dest_manifest(mock_authenticate):
    merger = manifest_list_merger.ManifestListMerger(
        "quay.io/src/image:1",
        "quay.io/dest/image:1",
        "src-quay.io",
        "src-user",
        "src-pass",
        "dest-user",
        "dest-pass",
    )

    with requests_mock.Mocker() as m:
        m.get(
            "https://src-quay.io/v2/src/image/manifests/1",
            json=new_ml,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/dest/image/manifests/1",
            [
                {"headers": {"some-header": "value"}, "status_code": 401},
                {"status_code": 401},
            ],
        )

        created_ml = merger.merge_manifest_lists_selected_architectures(["arm64", "s390x"])
        assert m.call_count == 3
        created_ml["manifests"].sort(key=lambda manifest: manifest["digest"])
        expected_ml = deepcopy(merged_ml3)
        expected_ml["manifests"].sort(key=lambda manifest: manifest["digest"])

        assert created_ml == expected_ml


def test_merge_selected_architectures_raises_unrelated_error():
    merger = manifest_list_merger.ManifestListMerger(
        "quay.io/src/image:1",
        "quay.io/dest/image:1",
        "src-quay.io",
        "src-user",
        "src-pass",
        "dest-user",
        "dest-pass",
    )

    with requests_mock.Mocker() as m:
        m.get(
            "https://src-quay.io/v2/src/image/manifests/1",
            json=new_ml,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/dest/image/manifests/1",
            status_code=500,
        )

        with pytest.raises(requests.exceptions.HTTPError, match=".*500 Server Error.*"):
            merger.merge_manifest_lists_selected_architectures(["arm64", "s390x"])
        assert m.call_count == 2


def test_merge_manifest_lists_selected_architectures_missing_client():
    merger = manifest_list_merger.ManifestListMerger("quay.io/src/image:1", "quay.io/dest/image:1")

    with pytest.raises(RuntimeError, match="QuayClient instance must be set"):
        merger.merge_manifest_lists_selected_architectures(["arm64", "s390x"])
