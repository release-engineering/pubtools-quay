import mock
import pytest
import requests

from pubtools._quay import signature_remover

# flake8: noqa: E501


def test_init():
    sig_remover = signature_remover.SignatureRemover()

    assert sig_remover.quay_host == "quay.io"
    assert sig_remover.quay_user is None
    assert sig_remover.quay_password is None
    assert sig_remover._quay_client is None


@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_initialize_quay_client(mock_quay_client):
    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password"
    )

    assert sig_remover.quay_host == "quay.io"
    assert sig_remover.quay_user == "some-user"
    assert sig_remover.quay_password == "some-password"
    assert sig_remover._quay_client is None
    assert sig_remover.quay_client == mock_quay_client.return_value
    assert sig_remover._quay_client == mock_quay_client.return_value


def test_set_quay_client():
    mock_quay_client = mock.MagicMock()
    sig_remover = signature_remover.SignatureRemover()

    assert sig_remover._quay_client is None
    sig_remover.set_quay_client(mock_quay_client)
    assert sig_remover._quay_client == mock_quay_client
    assert sig_remover.quay_client == mock_quay_client


def test_quay_client_error():
    sig_remover = signature_remover.SignatureRemover()

    with pytest.raises(ValueError, match="No instance of QuayClient.*"):
        sig_remover.quay_client


@mock.patch("json.dump")
@mock.patch("tempfile.NamedTemporaryFile")
@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
def test_get_signatures_from_pyxis(mock_run_entrypoint, mock_tempfile, mock_json_dump):
    expected_data1 = [{"some": "data"}, {"other": "data"}]
    expected_data2 = [{"some-other": "data"}]
    mock_run_entrypoint.side_effect = [iter(expected_data1), iter(expected_data2)]

    temp_filename = "/var/pubtools_quay_get_signatures_ABC123"
    mock_tempfile.return_value.__enter__.return_value.name = temp_filename

    sig_remover = signature_remover.SignatureRemover()
    sig_remover.MAX_MANIFEST_DIGESTS_PER_SEARCH_REQUEST = 2
    sig_data = sig_remover.get_signatures_from_pyxis(
        ["digest1", "digest2", "digest3", "digest3"],
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
    )

    for i, data in enumerate(sig_data):
        assert data == (expected_data1 + expected_data2)[i]

    assert mock_run_entrypoint.call_count == 2
    assert mock_run_entrypoint.mock_calls[0] == mock.call(
        ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
        "pubtools-pyxis-get-signatures",
        [
            "--pyxis-server",
            "pyxis-server.com",
            "--pyxis-ssl-crtfile",
            "some-principal",
            "--pyxis-ssl-keyfile",
            "some-keytab",
            "--manifest-digest",
            "@/var/pubtools_quay_get_signatures_ABC123",
        ],
        {},
    )
    assert mock_run_entrypoint.mock_calls[1] == mock.call(
        ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
        "pubtools-pyxis-get-signatures",
        [
            "--pyxis-server",
            "pyxis-server.com",
            "--pyxis-ssl-crtfile",
            "some-principal",
            "--pyxis-ssl-keyfile",
            "some-keytab",
            "--manifest-digest",
            "@/var/pubtools_quay_get_signatures_ABC123",
        ],
        {},
    )

    assert mock_json_dump.call_count == 2
    assert mock_json_dump.mock_calls[0][1][0] == ["digest1", "digest2"]
    assert mock_json_dump.mock_calls[1][1][0] == ["digest3"]


@mock.patch("pubtools._quay.signature_remover.tempfile.NamedTemporaryFile")
@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
def test_remove_signatures_from_pyxis(mock_run_entrypoint, mock_temp_file):
    mock_temp_file.return_value.__enter__.return_value.name = "some-tmp-file"
    sig_remover = signature_remover.SignatureRemover()

    sig_remover.remove_signatures_from_pyxis(
        ["id1", "id2", "id3"], "pyxis-server.com", "some-principal", "some-keytab", 7
    )

    mock_run_entrypoint.assert_called_once_with(
        ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-delete-signatures"),
        "pubtools-pyxis-delete-signatures",
        [
            "--pyxis-server",
            "pyxis-server.com",
            "--pyxis-ssl-crtfile",
            "some-principal",
            "--pyxis-ssl-keyfile",
            "some-keytab",
            "--request-threads",
            "7",
            "--ids",
            "@some-tmp-file",
        ],
        {},
    )


@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_get_repository_digests(
    mock_quay_client, repo_api_data, manifest_list_data, v2s2_manifest_data
):
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {"name": "namespace/repo", "tags": ["1", "2", "3", "4"]}
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags
    mock_get_manifest_digest = mock.MagicMock()
    mock_get_manifest_digest.return_value = (
        "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb"
    )
    mock_quay_client.return_value.get_manifest_digest = mock_get_manifest_digest
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.side_effect = [
        manifest_list_data,
        manifest_list_data,
        v2s2_manifest_data,
        v2s2_manifest_data,
    ]
    mock_quay_client.return_value.get_manifest = mock_get_manifest
    mock_quay_client.MANIFEST_LIST_TYPE = (
        "application/vnd.docker.distribution.manifest.list.v2+json"
    )
    mock_quay_client.MANIFEST_V2S2_TYPE = "application/vnd.docker.distribution.manifest.v2+json"

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password"
    )
    digests = sig_remover.get_repository_digests("namespace/repo")

    mock_get_repository_tags.assert_called_once_with("namespace/repo")
    assert mock_get_manifest_digest.call_count == 2
    assert mock_get_manifest_digest.call_args_list[0] == mock.call("quay.io/namespace/repo:3")
    assert mock_get_manifest_digest.call_args_list[1] == mock.call("quay.io/namespace/repo:4")
    assert mock_get_manifest.call_count == 4
    assert mock_get_manifest.call_args_list[0] == mock.call("quay.io/namespace/repo:1")
    assert mock_get_manifest.call_args_list[1] == mock.call("quay.io/namespace/repo:2")
    assert mock_get_manifest.call_args_list[2] == mock.call("quay.io/namespace/repo:3")
    assert mock_get_manifest.call_args_list[3] == mock.call("quay.io/namespace/repo:4")

    assert digests == [
        "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
        "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
        "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
        "sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
        "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
    ]


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.remove_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_repository_digests")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_remove_repository_signatures(
    mock_quay_client,
    mock_get_repo_digests,
    mock_get_signatures,
    mock_remove_signatures,
):
    mock_get_repo_digests.return_value = ["digest1", "digest2"]
    mock_get_signatures.return_value = [
        {
            "repository": "namespace/repo",
            "_id": "id1",
            "reference": "some-registry.com/redhat-namespace/old-image:5",
            "manifest_digest": "sha256:a1a1a1",
            "sig_key_id": "sig-key",
        },
        {
            "repository": "namespace/repo",
            "_id": "id2",
            "reference": "some-registry.com/redhat-namespace/old-image:6",
            "manifest_digest": "sha256:b2b2b2",
            "sig_key_id": "sig-key",
        },
        {
            "repository": "namespace/different-repo",
            "_id": "id3",
            "reference": "some-registry.com/redhat-namespace/old-image:7",
            "manifest_digest": "sha256:c3c3c3",
            "sig_key_id": "sig-key",
        },
    ]

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password"
    )
    sig_remover.remove_repository_signatures(
        "namespace/repo",
        "internal-namespace",
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
        7,
    )

    mock_get_repo_digests.assert_called_once_with("internal-namespace/namespace----repo")
    mock_get_signatures.assert_called_once_with(
        ["digest1", "digest2"], "pyxis-server.com", "some-principal", "some-keytab"
    )
    mock_remove_signatures.assert_called_once_with(
        ["id1", "id2"], "pyxis-server.com", "some-principal", "some-keytab", 7
    )


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.remove_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_repository_digests")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_remove_repository_signatures_none_to_remove(
    mock_quay_client,
    mock_get_repo_digests,
    mock_get_signatures,
    mock_remove_signatures,
):
    mock_get_repo_digests.return_value = ["digest1", "digest2"]
    mock_get_signatures.return_value = [
        {"repository": "namespace/different-repo", "_id": "id3"},
    ]

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password"
    )
    sig_remover.remove_repository_signatures(
        "namespace/repo",
        "internal-namespace",
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
        7,
    )

    mock_get_repo_digests.assert_called_once_with("internal-namespace/namespace----repo")
    mock_get_signatures.assert_called_once_with(
        ["digest1", "digest2"], "pyxis-server.com", "some-principal", "some-keytab"
    )
    mock_remove_signatures.assert_not_called()


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.remove_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_remove_tag_signatures_multiarch(
    mock_quay_client,
    mock_get_signatures,
    mock_remove_signatures,
    manifest_list_data,
):
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {
        "name": "external-repo/other-image",
        "tags": ["1", "2", "3", "4"],
    }
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = manifest_list_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    mock_get_signatures.return_value = [
        {
            "repository": "external-repo/external-image",
            "reference": "redhat.com/external-repo/external-image:1",
            "_id": "id1",
            "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "sig_key_id": "sig-key",
        },
        {
            "repository": "external-repo/external-image",
            "reference": "redhat.com/external-repo/external-image:1",
            "_id": "id2",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
            "sig_key_id": "sig-key",
        },
        {
            "repository": "external-repo/other-image",
            "reference": "redhat.com/external-repo/other-image:1",
            "_id": "id3",
            "manifest_digest": "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "sig_key_id": "sig-key",
        },
        {
            "repository": "external-repo/external-image",
            "reference": "redhat.com/external-repo/external-image:2",
            "_id": "id4",
            "manifest_digest": "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "sig_key_id": "sig-key",
        },
    ]

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password"
    )
    sig_remover.remove_tag_signatures(
        "quay.io/internal-namespace/external-repo----external-image:1",
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
        7,
    )

    mock_get_repository_tags.assert_called_once_with(
        "internal-namespace/external-repo----external-image"
    )
    mock_get_manifest.assert_called_once_with(
        "quay.io/internal-namespace/external-repo----external-image:1"
    )
    mock_get_signatures.assert_called_once_with(
        [
            "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        ],
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
    )
    mock_remove_signatures.assert_called_once_with(
        ["id1", "id2"], "pyxis-server.com", "some-principal", "some-keytab", 7
    )


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.remove_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_remove_tag_signatures_non_existent_tag(
    mock_quay_client,
    mock_get_signatures,
    mock_remove_signatures,
    manifest_list_data,
):
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {
        "name": "external-repo/other-image",
        "tags": ["1", "2", "3", "4"],
    }
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = manifest_list_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password"
    )
    sig_remover.remove_tag_signatures(
        "quay.io/internal-namespace/external-repo----external-image:5",
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
        7,
    )

    mock_get_repository_tags.assert_called_once_with(
        "internal-namespace/external-repo----external-image"
    )
    mock_get_manifest.assert_not_called()
    mock_get_signatures.assert_not_called()
    mock_remove_signatures.assert_not_called()


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.remove_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_remove_tag_signatures_source(
    mock_quay_client,
    mock_get_signatures,
    mock_remove_signatures,
    v2s2_manifest_data,
):
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {
        "name": "external-repo/other-image",
        "tags": ["1", "2", "3", "4"],
    }
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = v2s2_manifest_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest
    mock_get_manifest_digest = mock.MagicMock()
    mock_get_manifest_digest.return_value = (
        "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb"
    )
    mock_quay_client.return_value.get_manifest_digest = mock_get_manifest_digest

    mock_get_signatures.return_value = [
        {
            "repository": "external-repo/external-image",
            "reference": "redhat.com/external-repo/external-image:3",
            "_id": "id1",
            "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "sig_key_id": "sig-key",
        },
        {
            "repository": "external-repo/external-image",
            "reference": "redhat.com/external-repo/external-image:3",
            "_id": "id2",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
            "sig_key_id": "sig-key",
        },
        {
            "repository": "external-repo/other-image",
            "reference": "redhat.com/external-repo/other-image:3",
            "_id": "id3",
            "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "sig_key_id": "sig-key",
        },
        {
            "repository": "external-repo/external-image",
            "reference": "redhat.com/external-repo/external-image:4",
            "_id": "id4",
            "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "sig_key_id": "sig-key",
        },
    ]

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password"
    )
    sig_remover.remove_tag_signatures(
        "quay.io/internal-namespace/external-repo----external-image:3",
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
        7,
    )

    mock_get_repository_tags.assert_called_once_with(
        "internal-namespace/external-repo----external-image"
    )
    mock_get_manifest.assert_called_once_with(
        "quay.io/internal-namespace/external-repo----external-image:3"
    )
    mock_get_signatures.assert_called_once_with(
        ["sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb"],
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
    )
    mock_remove_signatures.assert_called_once_with(
        ["id1"], "pyxis-server.com", "some-principal", "some-keytab", 7
    )


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.remove_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_remove_tag_signatures_digest(
    mock_quay_client,
    mock_get_signatures,
    mock_remove_signatures,
    manifest_list_data,
):
    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password"
    )
    with pytest.raises(ValueError, match=".*removed must be specified by tag."):
        sig_remover.remove_tag_signatures(
            "quay.io/some-namespace/some-repo@sha256:a1a1a1",
            "pyxis-server.com",
            "some-principal",
            "some-keytab",
            7,
        )

    mock_get_signatures.assert_not_called()
    mock_remove_signatures.assert_not_called()


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.remove_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_remove_tag_signatures_no_signatures(
    mock_quay_client,
    mock_get_signatures,
    mock_remove_signatures,
    manifest_list_data,
):
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {
        "name": "external-repo/other-image",
        "tags": ["1", "2", "3", "4"],
    }
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = manifest_list_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    mock_get_signatures.return_value = [
        {
            "repository": "external-repo/external-image",
            "reference": "redhat.com/external-repo/external-image:2",
            "_id": "id1",
            "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
        },
        {
            "repository": "external-repo/external-image",
            "reference": "redhat.com/external-repo/external-image:3",
            "_id": "id2",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        },
        {
            "repository": "external-repo/other-image",
            "reference": "redhat.com/external-repo/other-image:1",
            "_id": "id3",
            "manifest_digest": "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
        },
    ]

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password"
    )
    sig_remover.remove_tag_signatures(
        "quay.io/internal-namespace/external-repo----external-image:1",
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
        7,
    )

    mock_remove_signatures.assert_not_called()


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.remove_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_remove_tag_signatures_exclude_by_claims(
    mock_quay_client,
    mock_get_signatures,
    mock_remove_signatures,
    manifest_list_data,
):
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {
        "name": "external-repo/other-image",
        "tags": ["1", "2", "3", "4"],
    }
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = manifest_list_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    mock_get_signatures.return_value = [
        {
            "repository": "external-repo/external-image",
            "reference": "redhat.com/external-repo/external-image:1",
            "_id": "id1",
            "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "sig_key_id": "sig-key",
        },
        {
            "repository": "external-repo/external-image",
            "reference": "redhat.com/external-repo/external-image:1",
            "_id": "id2",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
            "sig_key_id": "sig-key",
        },
        {
            "repository": "external-repo/other-image",
            "reference": "redhat.com/external-repo/other-image:1",
            "_id": "id3",
            "manifest_digest": "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "sig_key_id": "sig-key",
        },
    ]

    claim_messages = [
        {
            "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "docker_reference": "redhat.com/external-repo/external-image:1",
        },
        {
            "manifest_digest": "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "docker_reference": "redhat.com/external-repo/external-image:1",
        },
    ]

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password"
    )
    sig_remover.remove_tag_signatures(
        "quay.io/internal-namespace/external-repo----external-image:1",
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
        7,
        exclude_by_claims=claim_messages,
    )

    mock_get_repository_tags.assert_called_once_with(
        "internal-namespace/external-repo----external-image"
    )
    mock_get_manifest.assert_called_once_with(
        "quay.io/internal-namespace/external-repo----external-image:1"
    )
    mock_get_signatures.assert_called_once_with(
        [
            "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        ],
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
    )
    mock_remove_signatures.assert_called_once_with(
        ["id2"], "pyxis-server.com", "some-principal", "some-keytab", 7
    )


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.remove_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_remove_tag_signatures_selected_archs(
    mock_quay_client,
    mock_get_signatures,
    mock_remove_signatures,
    repo_api_data,
    manifest_list_data,
):
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {
        "name": "external-repo/other-image",
        "tags": ["1", "2", "3", "4"],
    }
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = manifest_list_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    mock_get_signatures.return_value = [
        {
            "repository": "external-repo/external-image",
            "reference": "redhat.com/external-repo/external-image:1",
            "_id": "id1",
            "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "sig_key_id": "sig-key",
        },
        {
            "repository": "external-repo/external-image",
            "reference": "redhat.com/external-repo/external-image:1",
            "_id": "id2",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
            "sig_key_id": "sig-key",
        },
        {
            "repository": "external-repo/other-image",
            "reference": "redhat.com/external-repo/other-image:1",
            "_id": "id3",
            "manifest_digest": "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "sig_key_id": "sig-key",
        },
    ]

    selected_archs = ["ppc64le", "arm64"]

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password"
    )
    sig_remover.remove_tag_signatures(
        "quay.io/internal-namespace/external-repo----external-image:1",
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
        7,
        remove_archs=selected_archs,
    )

    mock_get_repository_tags.assert_called_once_with(
        "internal-namespace/external-repo----external-image"
    )
    mock_get_manifest.assert_called_once_with(
        "quay.io/internal-namespace/external-repo----external-image:1"
    )
    mock_get_signatures.assert_called_once_with(
        [
            "sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
        ],
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
    )
    mock_remove_signatures.assert_called_once_with(
        ["id1"], "pyxis-server.com", "some-principal", "some-keytab", 7
    )


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_get_index_image_signatures_no_claims(
    mock_quay_client, mock_get_signatures, manifest_list_data
):
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = manifest_list_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    mock_get_signatures.return_value = [
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id1",
            "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
        },
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id2",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        },
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id3",
            "manifest_digest": "sha256:dfgdfgdfg",
        },
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:2",
            "_id": "id4",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        },
        {
            "repository": "different-repo/index-image",
            "reference": "redhat.com/different-repo/index-image:1",
            "_id": "id5",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        },
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id6",
            "manifest_digest": "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
        },
    ]

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password", quay_api_token="some-token"
    )

    signatures = sig_remover.get_index_image_signatures(
        "quay.io/internal-namespace/index-repo----index-image:1",
        [],
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
    )

    mock_get_manifest.assert_called_once_with(
        "quay.io/internal-namespace/index-repo----index-image:1",
        media_type=mock_quay_client.MANIFEST_LIST_TYPE,
    )
    mock_get_signatures.assert_called_once_with(
        [
            "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        ],
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
    )
    assert signatures == [
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id1",
            "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
        },
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id2",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        },
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id6",
            "manifest_digest": "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
        },
    ]


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_get_index_image_signatures_claims(
    mock_quay_client, mock_get_signatures, manifest_list_data
):
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = manifest_list_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    mock_get_signatures.return_value = [
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id1",
            "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
        },
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id2",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        },
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id3",
            "manifest_digest": "sha256:dfgdfgdfg",
        },
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:2",
            "_id": "id4",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        },
        {
            "repository": "different-repo/index-image",
            "reference": "redhat.com/different-repo/index-image:1",
            "_id": "id5",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        },
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id6",
            "manifest_digest": "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
        },
    ]

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password", quay_api_token="some-token"
    )

    claim_messages = [
        {
            "manifest_digest": "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            "repo": "index-repo/index-image",
            "docker_reference": "redhat.com/index-repo/index-image:1",
        },
        {
            "manifest_digest": "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            "repo": "index-repo/index-image",
            "docker_reference": "redhat.com/index-repo/index-image:2",
        },
    ]

    signatures = sig_remover.get_index_image_signatures(
        "quay.io/internal-namespace/index-repo----index-image:1",
        claim_messages,
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
    )

    mock_get_manifest.assert_called_once_with(
        "quay.io/internal-namespace/index-repo----index-image:1",
        media_type=mock_quay_client.MANIFEST_LIST_TYPE,
    )
    mock_get_signatures.assert_called_once_with(
        [
            "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        ],
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
    )
    assert signatures == [
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id1",
            "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
        },
        {
            "repository": "index-repo/index-image",
            "reference": "redhat.com/index-repo/index-image:1",
            "_id": "id2",
            "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        },
    ]


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_get_index_image_signatures_digest(
    mock_quay_client, mock_get_signatures, manifest_list_data
):
    mock_get_manifest = mock.MagicMock()
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password", quay_api_token="some-token"
    )

    with pytest.raises(ValueError, match="Please specify the index image via tag"):
        sig_remover.get_index_image_signatures(
            "quay.io/internal-namespace/index-repo----index-image@sha256:a1a1a1a1",
            [],
            "pyxis-server.com",
            "some-principal",
            "some-keytab",
        )

    mock_get_manifest.assert_not_called()
    mock_get_signatures.assert_not_called()


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_get_index_image_signatures_no_manifest(
    mock_quay_client, mock_get_signatures, manifest_list_data
):
    response = mock.MagicMock()
    response.status_code = 404

    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.side_effect = requests.exceptions.HTTPError("missing", response=response)
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password", quay_api_token="some-token"
    )

    signatures = sig_remover.get_index_image_signatures(
        "quay.io/internal-namespace/index-repo----index-image:1",
        [],
        "pyxis-server.com",
        "some-principal",
        "some-keytab",
    )

    mock_get_manifest.assert_called_once_with(
        "quay.io/internal-namespace/index-repo----index-image:1",
        media_type=mock_quay_client.MANIFEST_LIST_TYPE,
    )
    mock_get_signatures.assert_not_called()
    assert signatures == []


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
def test_get_index_image_signatures_server_error(
    mock_quay_client, mock_get_signatures, manifest_list_data
):
    response = mock.MagicMock()
    response.status_code = 500

    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.side_effect = requests.exceptions.HTTPError("server error", response=response)
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password", quay_api_token="some-token"
    )

    with pytest.raises(requests.exceptions.HTTPError, match="server error"):
        sig_remover.get_index_image_signatures(
            "quay.io/internal-namespace/index-repo----index-image:1",
            [],
            "pyxis-server.com",
            "some-principal",
            "some-keytab",
        )

    mock_get_manifest.assert_called_once_with(
        "quay.io/internal-namespace/index-repo----index-image:1",
        media_type=mock_quay_client.MANIFEST_LIST_TYPE,
    )
    mock_get_signatures.assert_not_called()
