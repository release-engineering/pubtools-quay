import mock
import pytest

from pubtools._quay import remove_repo


@mock.patch("pubtools._quay.remove_repo.remove_repositories")
def test_arg_constructor_required_args(mock_remove_repositories):
    required_args = [
        "dummy",
        "--repositories",
        "namespace/image",
        "--quay-org",
        "quay-organization",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-ssl-crtfile",
        "/path/to/file.crt",
        "--pyxis-ssl-keyfile",
        "/path/to/file.key",
    ]
    remove_repo.remove_repositories_main(required_args)
    _, called_args = mock_remove_repositories.call_args

    assert called_args["repositories"] == "namespace/image"
    assert called_args["quay_org"] == "quay-organization"
    assert called_args["quay_user"] == "some-user"
    assert called_args["quay_password"] == "some-password"
    assert called_args["quay_api_token"] == "some-token"
    assert called_args["pyxis_server"] == "pyxis-url.com"
    assert called_args["pyxis_ssl_crtfile"] == "/path/to/file.crt"
    assert called_args["pyxis_ssl_keyfile"] == "/path/to/file.key"


@mock.patch.dict("os.environ", {"QUAY_API_TOKEN": "api_token", "QUAY_PASSWORD": "some-password"})
@mock.patch("pubtools._quay.remove_repo.remove_repositories")
def test_arg_constructor_all_args(mock_remove_repositories):
    all_args = [
        "dummy",
        "--repositories",
        "namespace/image",
        "--quay-org",
        "quay-organization",
        "--quay-user",
        "some-user",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-ssl-crtfile",
        "/path/to/file.crt",
        "--pyxis-ssl-keyfile",
        "/path/to/file.key",
    ]
    remove_repo.remove_repositories_main(all_args)
    _, called_args = mock_remove_repositories.call_args

    assert called_args["repositories"] == "namespace/image"
    assert called_args["quay_org"] == "quay-organization"
    assert called_args["quay_user"] == "some-user"
    assert called_args["quay_password"] == "some-password"
    assert called_args["pyxis_server"] == "pyxis-url.com"
    assert called_args["pyxis_ssl_crtfile"] == "/path/to/file.crt"
    assert called_args["pyxis_ssl_keyfile"] == "/path/to/file.key"
    assert called_args["quay_api_token"] == "api_token"


@mock.patch("pubtools._quay.remove_repo.remove_repositories")
def test_args_missing_repository(mock_remove_repositories):
    wrong_args = [
        "dummy",
        "--quay-org",
        "quay-organization",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-ssl-crtfile",
        "/path/to/file.crt",
        "--pyxis-ssl-keyfile",
        "/path/to/file.key",
    ]

    with pytest.raises(SystemExit) as system_error:
        remove_repo.remove_repositories_main(wrong_args)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2
    mock_remove_repositories.assert_not_called()


@mock.patch("pubtools._quay.remove_repo.remove_repositories")
def test_args_missing_api_token(mock_remove_repositories):
    wrong_args = [
        "dummy",
        "--repositories",
        "namespace/image",
        "--quay-org",
        "quay-organization",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-ssl-crtfile",
        "/path/to/file.crt",
        "--pyxis-ssl-keyfile",
        "/path/to/file.key",
    ]

    with pytest.raises(ValueError, match="--quay-api-token must be specified"):
        remove_repo.remove_repositories_main(wrong_args)

    mock_remove_repositories.assert_not_called()


@mock.patch("pubtools._quay.remove_repo.remove_repositories")
def test_args_missing_quay_password(mock_remove_repositories):
    wrong_args = [
        "dummy",
        "--repositories",
        "namespace/image",
        "--quay-org",
        "quay-organization",
        "--quay-user",
        "some-user",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-ssl-crtfile",
        "/path/to/file.crt",
        "--pyxis-ssl-keyfile",
        "/path/to/file.key",
    ]

    with pytest.raises(ValueError, match="--quay-password must be specified"):
        remove_repo.remove_repositories_main(wrong_args)

    mock_remove_repositories.assert_not_called()


@mock.patch("pubtools._quay.remove_repo.SignatureRemover")
@mock.patch("pubtools._quay.remove_repo.QuayApiClient")
def test_run(mock_quay_api_client, mock_signature_remover, hookspy):
    args = [
        "dummy",
        "--repositories",
        "namespace/image",
        "--quay-org",
        "quay-organization",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-ssl-crtfile",
        "/path/to/file.crt",
        "--pyxis-ssl-keyfile",
        "/path/to/file.key",
    ]
    mock_delete_repo = mock.MagicMock()
    mock_quay_api_client.return_value.delete_repository = mock_delete_repo
    mock_remove_repository_signatures = mock.MagicMock()
    mock_signature_remover.return_value.remove_repository_signatures = (
        mock_remove_repository_signatures
    )

    remove_repo.remove_repositories_main(args)

    mock_quay_api_client.assert_called_once_with("some-token")
    mock_signature_remover.assert_called_once_with(
        quay_user="some-user", quay_password="some-password"
    )
    mock_remove_repository_signatures.assert_called_once_with(
        "namespace/image",
        "quay-organization",
        "pyxis-url.com",
        "/path/to/file.crt",
        "/path/to/file.key",
        7,
    )
    mock_delete_repo.assert_called_once_with("quay-organization/namespace----image")

    assert hookspy == [
        ("task_start", {}),
        ("quay_repositories_removed", {"repository_ids": ["namespace/image"]}),
        ("task_stop", {"failed": False}),
    ]


@mock.patch("pubtools._quay.remove_repo.SignatureRemover")
@mock.patch("pubtools._quay.remove_repo.QuayApiClient")
def test_run_multiple_repos(mock_quay_api_client, mock_signature_remover):
    args = [
        "dummy",
        "--repositories",
        "namespace/image,namespace/image2",
        "--quay-org",
        "quay-organization",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-ssl-crtfile",
        "/path/to/file.crt",
        "--pyxis-ssl-keyfile",
        "/path/to/file.key",
    ]
    mock_delete_repo = mock.MagicMock()
    mock_quay_api_client.return_value.delete_repository = mock_delete_repo
    mock_remove_repository_signatures = mock.MagicMock()
    mock_signature_remover.return_value.remove_repository_signatures = (
        mock_remove_repository_signatures
    )

    remove_repo.remove_repositories_main(args)

    mock_quay_api_client.assert_called_once_with("some-token")
    mock_signature_remover.assert_called_once_with(
        quay_user="some-user", quay_password="some-password"
    )
    assert mock_remove_repository_signatures.call_count == 2
    assert mock_remove_repository_signatures.call_args_list[0] == mock.call(
        "namespace/image",
        "quay-organization",
        "pyxis-url.com",
        "/path/to/file.crt",
        "/path/to/file.key",
        7,
    )
    assert mock_remove_repository_signatures.call_args_list[1] == mock.call(
        "namespace/image2",
        "quay-organization",
        "pyxis-url.com",
        "/path/to/file.crt",
        "/path/to/file.key",
        7,
    )

    assert mock_delete_repo.call_count == 2
    assert mock_delete_repo.call_args_list[0] == mock.call("quay-organization/namespace----image")
    assert mock_delete_repo.call_args_list[1] == mock.call("quay-organization/namespace----image2")
