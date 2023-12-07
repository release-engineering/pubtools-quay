import mock
import pytest

from pubtools._quay import clear_repo


@mock.patch("pubtools._quay.clear_repo.clear_repositories")
def test_arg_constructor_required_args(mock_clear_repositories):
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
    clear_repo.clear_repositories_main(required_args)
    _, called_args = mock_clear_repositories.call_args

    assert called_args["repositories"] == "namespace/image"
    assert called_args["quay_org"] == "quay-organization"
    assert called_args["quay_user"] == "some-user"
    assert called_args["quay_password"] == "some-password"
    assert called_args["quay_api_token"] == "some-token"
    assert called_args["pyxis_server"] == "pyxis-url.com"
    assert called_args["pyxis_ssl_crtfile"] == "/path/to/file.crt"
    assert called_args["pyxis_ssl_keyfile"] == "/path/to/file.key"


@mock.patch.dict("os.environ", {"QUAY_API_TOKEN": "api_token", "QUAY_PASSWORD": "some-password"})
@mock.patch("pubtools._quay.clear_repo.clear_repositories")
def test_arg_constructor_all_args(mock_clear_repositories):
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
    clear_repo.clear_repositories_main(all_args)
    _, called_args = mock_clear_repositories.call_args

    assert called_args["repositories"] == "namespace/image"
    assert called_args["quay_org"] == "quay-organization"
    assert called_args["quay_user"] == "some-user"
    assert called_args["quay_password"] == "some-password"
    assert called_args["pyxis_server"] == "pyxis-url.com"
    assert called_args["pyxis_ssl_crtfile"] == "/path/to/file.crt"
    assert called_args["pyxis_ssl_keyfile"] == "/path/to/file.key"
    assert called_args["quay_api_token"] == "api_token"


@mock.patch("pubtools._quay.clear_repo.clear_repositories")
def test_args_missing_repositories(mock_clear_repositories):
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
        clear_repo.clear_repositories_main(wrong_args)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2
    mock_clear_repositories.assert_not_called()


@mock.patch("pubtools._quay.clear_repo.clear_repositories")
def test_args_missing_api_token(mock_clear_repositories):
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
        clear_repo.clear_repositories_main(wrong_args)

    mock_clear_repositories.assert_not_called()


@mock.patch("pubtools._quay.clear_repo.clear_repositories")
def test_args_missing_quay_password(mock_clear_repositories):
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
        clear_repo.clear_repositories_main(wrong_args)

    mock_clear_repositories.assert_not_called()


@mock.patch("pubtools._quay.clear_repo.untag_images")
@mock.patch("pubtools._quay.clear_repo.SignatureRemover")
@mock.patch("pubtools._quay.clear_repo.QuayClient")
def test_run(mock_quay_client, mock_signature_remover, mock_untag_images):
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
    mock_get_repo_tags = mock.MagicMock()
    mock_get_repo_tags.return_value = {"tags": ["1", "2"]}
    mock_quay_client.return_value.get_repository_tags = mock_get_repo_tags
    mock_set_quay_client = mock.MagicMock()
    mock_remove_repository_signatures = mock.MagicMock()
    mock_signature_remover.return_value.set_quay_client = mock_set_quay_client
    mock_signature_remover.return_value.remove_repository_signatures = (
        mock_remove_repository_signatures
    )

    clear_repo.clear_repositories_main(args)

    mock_quay_client.assert_called_once_with("some-user", "some-password")
    mock_signature_remover.assert_called_once_with()
    mock_set_quay_client.assert_called_once_with(mock_quay_client.return_value)
    mock_remove_repository_signatures.assert_called_once_with(
        "namespace/image",
        "quay-organization",
        "pyxis-url.com",
        "/path/to/file.crt",
        "/path/to/file.key",
        7,
    )
    mock_get_repo_tags.assert_called_once_with("quay-organization/namespace----image")
    mock_untag_images.assert_called_once_with(
        [
            "quay.io/quay-organization/namespace----image:1",
            "quay.io/quay-organization/namespace----image:2",
        ],
        "some-token",
        remove_last=True,
        quay_user="some-user",
        quay_password="some-password",
    )


@mock.patch("pubtools._quay.clear_repo.untag_images")
@mock.patch("pubtools._quay.clear_repo.SignatureRemover")
@mock.patch("pubtools._quay.clear_repo.QuayClient")
def test_run_multiple_repos(mock_quay_client, mock_signature_remover, mock_untag_images, hookspy):
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
    mock_get_repo_tags = mock.MagicMock()
    mock_get_repo_tags.side_effect = [
        {"tags": ["1", "2"]},
        {"tags": ["3", "4"]},
    ]
    mock_quay_client.return_value.get_repository_tags = mock_get_repo_tags
    mock_set_quay_client = mock.MagicMock()
    mock_remove_repository_signatures = mock.MagicMock()
    mock_signature_remover.return_value.set_quay_client = mock_set_quay_client
    mock_signature_remover.return_value.remove_repository_signatures = (
        mock_remove_repository_signatures
    )

    clear_repo.clear_repositories_main(args)

    mock_quay_client.assert_called_once_with("some-user", "some-password")
    mock_signature_remover.assert_called_once_with()
    mock_set_quay_client.assert_called_once_with(mock_quay_client.return_value)
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

    assert mock_get_repo_tags.call_count == 2
    assert mock_get_repo_tags.call_args_list[0] == mock.call("quay-organization/namespace----image")
    assert mock_get_repo_tags.call_args_list[1] == mock.call(
        "quay-organization/namespace----image2"
    )

    mock_untag_images.assert_called_once_with(
        [
            "quay.io/quay-organization/namespace----image2:3",
            "quay.io/quay-organization/namespace----image2:4",
            "quay.io/quay-organization/namespace----image:1",
            "quay.io/quay-organization/namespace----image:2",
        ],
        "some-token",
        remove_last=True,
        quay_user="some-user",
        quay_password="some-password",
    )

    # Should have activated these hooks.
    assert hookspy == [
        ("task_start", {}),
        (
            "quay_repositories_cleared",
            {"repository_ids": ["namespace/image", "namespace/image2"]},
        ),
        ("task_stop", {"failed": False}),
    ]
