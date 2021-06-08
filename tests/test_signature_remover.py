import mock
import pytest

from pubtools._quay import signature_remover


def test_init():
    sig_remover = signature_remover.SignatureRemover()

    assert sig_remover.quay_host == "quay.io"
    assert sig_remover.quay_api_token is None
    assert sig_remover.quay_user is None
    assert sig_remover.quay_password is None
    assert sig_remover._quay_client is None
    assert sig_remover._quay_api_client is None


@mock.patch("pubtools._quay.signature_remover.QuayApiClient")
def test_initialize_api_client(mock_quay_api_client):
    sig_remover = signature_remover.SignatureRemover(quay_api_token="some-token")

    assert sig_remover.quay_host == "quay.io"
    assert sig_remover.quay_api_token == "some-token"
    assert sig_remover._quay_api_client is None
    assert sig_remover.quay_api_client == mock_quay_api_client.return_value
    assert sig_remover._quay_api_client == mock_quay_api_client.return_value


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


def test_set_quay_api_client():
    mock_quay_api_client = mock.MagicMock()
    sig_remover = signature_remover.SignatureRemover()

    assert sig_remover._quay_api_client is None
    sig_remover.set_quay_api_client(mock_quay_api_client)
    assert sig_remover._quay_api_client == mock_quay_api_client
    assert sig_remover.quay_api_client == mock_quay_api_client


def test_set_quay_client():
    mock_quay_client = mock.MagicMock()
    sig_remover = signature_remover.SignatureRemover()

    assert sig_remover._quay_client is None
    sig_remover.set_quay_client(mock_quay_client)
    assert sig_remover._quay_client == mock_quay_client
    assert sig_remover.quay_client == mock_quay_client


def test_quay_api_client_error():
    sig_remover = signature_remover.SignatureRemover()

    with pytest.raises(ValueError, match="No instance of QuayApiClient.*"):
        sig_remover.quay_api_client


def test_quay_client_error():
    sig_remover = signature_remover.SignatureRemover()

    with pytest.raises(ValueError, match="No instance of QuayClient.*"):
        sig_remover.quay_client


@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
def test_get_signatures_from_pyxis(mock_run_entrypoint):
    expected_data1 = [{"some": "data"}, {"other": "data"}]
    expected_data2 = [{"some-other": "data"}]
    mock_run_entrypoint.side_effect = [iter(expected_data1), iter(expected_data2)]

    sig_remover = signature_remover.SignatureRemover()
    sig_remover.MAX_MANIFEST_DIGESTS_PER_SEARCH_REQUEST = 2
    sig_data = sig_remover.get_signatures_from_pyxis(
        ["digest1", "digest2", "digest3"], "pyxis-server.com", "some-principal", "some-keytab"
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
            "--pyxis-krb-principal",
            "some-principal",
            "--pyxis-krb-ktfile",
            "some-keytab",
            "--manifest-digest",
            "digest1,digest2",
        ],
        {},
    )
    assert mock_run_entrypoint.mock_calls[1] == mock.call(
        ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
        "pubtools-pyxis-get-signatures",
        [
            "--pyxis-server",
            "pyxis-server.com",
            "--pyxis-krb-principal",
            "some-principal",
            "--pyxis-krb-ktfile",
            "some-keytab",
            "--manifest-digest",
            "digest3",
        ],
        {},
    )


@mock.patch("pubtools._quay.signature_remover.tempfile.NamedTemporaryFile")
@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
def test_remove_signatures_from_pyxis(mock_run_entrypoint, mock_temp_file):
    mock_temp_file.return_value.__enter__.return_value.name = "some-tmp-file"
    sig_remover = signature_remover.SignatureRemover()

    sig_remover.remove_signatures_from_pyxis(
        ["id1", "id2", "id3"], "pyxis-server.com", "some-principal", "some-keytab"
    )

    mock_run_entrypoint.assert_called_once_with(
        ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-delete-signatures"),
        "pubtools-pyxis-delete-signatures",
        [
            "--pyxis-server",
            "pyxis-server.com",
            "--pyxis-krb-principal",
            "some-principal",
            "--pyxis-krb-ktfile",
            "some-keytab",
            "--ids",
            "@some-tmp-file",
        ],
        {},
    )


@mock.patch("pubtools._quay.signature_remover.QuayClient")
@mock.patch("pubtools._quay.signature_remover.QuayApiClient")
def test_get_repository_digests(
    mock_quay_api_client, mock_quay_client, repo_api_data, manifest_list_data
):
    mock_get_repository_data = mock.MagicMock()
    mock_get_repository_data.return_value = repo_api_data
    mock_quay_api_client.return_value.get_repository_data = mock_get_repository_data
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = manifest_list_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password", quay_api_token="some-token"
    )
    digests = sig_remover.get_repository_digests("namespace/repo")

    mock_get_repository_data.assert_called_once_with("namespace/repo")
    assert mock_get_manifest.call_count == 2
    assert mock_get_manifest.call_args_list[0] == mock.call(
        "quay.io/namespace/repo:1", manifest_list=True
    )
    assert mock_get_manifest.call_args_list[1] == mock.call(
        "quay.io/namespace/repo:2", manifest_list=True
    )

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
@mock.patch("pubtools._quay.signature_remover.QuayApiClient")
def test_remove_repository_signatures(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_repo_digests,
    mock_get_signatures,
    mock_remove_signatures,
):
    mock_get_repo_digests.return_value = ["digest1", "digest2"]
    mock_get_signatures.return_value = [
        {"repository": "namespace/repo", "_id": "id1"},
        {"repository": "namespace/repo", "_id": "id2"},
        {"repository": "namespace/different-repo", "_id": "id3"},
    ]

    sig_remover = signature_remover.SignatureRemover(
        quay_user="some-user", quay_password="some-password", quay_api_token="some-token"
    )
    sig_remover.remove_repository_signatures(
        "namespace/repo", "internal-namespace", "pyxis-server.com", "some-principal", "some-keytab"
    )

    mock_get_repo_digests.assert_called_once_with("internal-namespace/namespace----repo")
    mock_get_signatures.assert_called_once_with(
        ["digest1", "digest2"], "pyxis-server.com", "some-principal", "some-keytab"
    )
    mock_remove_signatures.assert_called_once_with(
        ["id1", "id2"], "pyxis-server.com", "some-principal", "some-keytab"
    )


@mock.patch("pubtools._quay.signature_remover.SignatureRemover.remove_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_remover.SignatureRemover.get_repository_digests")
@mock.patch("pubtools._quay.signature_remover.QuayClient")
@mock.patch("pubtools._quay.signature_remover.QuayApiClient")
def test_remove_repository_signatures_none_to_remove(
    mock_quay_api_client,
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
        quay_user="some-user", quay_password="some-password", quay_api_token="some-token"
    )
    sig_remover.remove_repository_signatures(
        "namespace/repo", "internal-namespace", "pyxis-server.com", "some-principal", "some-keytab"
    )

    mock_get_repo_digests.assert_called_once_with("internal-namespace/namespace----repo")
    mock_get_signatures.assert_called_once_with(
        ["digest1", "digest2"], "pyxis-server.com", "some-principal", "some-keytab"
    )
    mock_remove_signatures.assert_not_called()
