import mock
import pytest

from pubtools._quay import clear_repo
from tests.utils.misc import GetManifestSideEffect


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
        "--quay-host",
        "quay-host.com",
    ]
    clear_repo.clear_repositories_main(required_args)
    repositories, settings = mock_clear_repositories.call_args[0]
    assert repositories == "namespace/image"
    assert settings["quay_org"] == "quay-organization"
    assert settings["quay_user"] == "some-user"
    assert settings["quay_password"] == "some-password"
    assert settings["quay_api_token"] == "some-token"
    assert settings["pyxis_server"] == "pyxis-url.com"
    assert settings["pyxis_ssl_crtfile"] == "/path/to/file.crt"
    assert settings["pyxis_ssl_keyfile"] == "/path/to/file.key"
    assert settings["quay_host"] == "quay-host.com"


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
        "--quay-host",
        "quay-host.com",
    ]
    clear_repo.clear_repositories_main(all_args)
    repositories, settings = mock_clear_repositories.call_args[0]

    assert repositories == "namespace/image"
    assert settings["quay_org"] == "quay-organization"
    assert settings["quay_user"] == "some-user"
    assert settings["quay_password"] == "some-password"
    assert settings["pyxis_server"] == "pyxis-url.com"
    assert settings["pyxis_ssl_crtfile"] == "/path/to/file.crt"
    assert settings["pyxis_ssl_keyfile"] == "/path/to/file.key"
    assert settings["quay_api_token"] == "api_token"
    assert settings["quay_host"] == "quay-host.com"


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
        "--quay-host",
        "quay-host.com",
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
        "--quay-host",
        "quay-host.com",
    ]

    with pytest.raises(ValueError, match="--quay-password must be specified"):
        clear_repo.clear_repositories_main(wrong_args)

    mock_clear_repositories.assert_not_called()


@mock.patch("pubtools._quay.clear_repo.untag_images")
@mock.patch("pubtools._quay.clear_repo.QuayClient")
def test_run(
    mock_quay_client,
    mock_untag_images,
    src_manifest_list,
    v2s1_manifest,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    signer_wrapper_remove_signatures,
):
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
        "--signers",
        "msg_signer",
        "--quay-host",
        "quay-host.com",
    ]
    mock_get_repo_tags = mock.MagicMock()
    mock_get_repo_tags.return_value = {"tags": ["1", "2"]}
    mock_quay_client.return_value.get_repository_tags = mock_get_repo_tags
    signer_wrapper_run_entry_point.return_value = [
        {
            "_id": 1,
            "manifest_digest": "sha256:3333333333",
            "reference": "registry.io/namespace/image:1",
            "sig_key_id": "key",
            "repository": "namespace/image",
        },
    ]
    mock_quay_client.return_value.get_manifest.side_effect = GetManifestSideEffect(
        v2s1_manifest, src_manifest_list, call_limit=16
    )
    clear_repo.clear_repositories_main(args)

    mock_quay_client.assert_called_once_with("some-user", "some-password")
    mock_get_repo_tags.assert_called_with("quay-organization/namespace----image")
    signer_wrapper_remove_signatures.assert_called_with(
        [1],
    )
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
@mock.patch("pubtools._quay.clear_repo.QuayClient")
def test_run_multiple_repos(
    mock_quay_client,
    mock_untag_images,
    hookspy,
    src_manifest_list,
    v2s1_manifest,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    signer_wrapper_remove_signatures,
):
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
        "--signers",
        "msg_signer",
        "--quay-host",
        "quay-host.com",
    ]
    mock_get_repo_tags = mock.MagicMock()
    mock_get_repo_tags.side_effect = [
        {"tags": ["1", "2"]},
        {"tags": ["3", "4"]},
        {"tags": ["1", "2"]},
        {"tags": ["3", "4"]},
    ]
    mock_quay_client.return_value.get_repository_tags = mock_get_repo_tags
    signer_wrapper_run_entry_point.return_value = [
        {
            "_id": 1,
            "manifest_digest": "sha256:5555555555",
            "reference": "registry.io/namespace/image2:3",
            "sig_key_id": "key",
            "repository": "namespace/image2",
        },
        {
            "_id": 2,
            "manifest_digest": "sha256:1111111111",
            "reference": "registry.io/namespace/image2:3",
            "sig_key_id": "key",
            "repository": "namespace/image2",
        },
    ]

    mock_quay_client.return_value.get_manifest.side_effect = GetManifestSideEffect(
        v2s1_manifest, src_manifest_list, call_limit=20
    )

    clear_repo.clear_repositories_main(args)

    mock_quay_client.assert_called_once_with("some-user", "some-password")
    assert mock_get_repo_tags.call_count == 4
    assert mock_get_repo_tags.call_args_list[0] == mock.call("quay-organization/namespace----image")
    assert mock_get_repo_tags.call_args_list[1] == mock.call(
        "quay-organization/namespace----image2"
    )
    assert mock_get_repo_tags.call_args_list[2] == mock.call("quay-organization/namespace----image")
    assert mock_get_repo_tags.call_args_list[3] == mock.call(
        "quay-organization/namespace----image2"
    )
    signer_wrapper_remove_signatures.assert_called_with(
        [1, 2],
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
        ("get_cert_key_paths", {"server_url": "pyxis-url.com"}),
        ("quay_repositories_cleared", {"repository_ids": ["namespace/image", "namespace/image2"]}),
        ("task_stop", {"failed": False}),
    ]
