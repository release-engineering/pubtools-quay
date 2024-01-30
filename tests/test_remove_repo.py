import mock
import pytest

from pubtools._quay import remove_repo

from tests.utils.misc import GetManifestSideEffect


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
        "--quay-host",
        "quay-host.com",
    ]
    remove_repo.remove_repositories_main(required_args)
    repositories, settings = mock_remove_repositories.call_args[0]
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
        "--quay-host",
        "quay-host.com",
    ]
    remove_repo.remove_repositories_main(all_args)
    repositories, called_kw_args = mock_remove_repositories.call_args[0]
    assert repositories == "namespace/image"
    assert called_kw_args["quay_org"] == "quay-organization"
    assert called_kw_args["quay_user"] == "some-user"
    assert called_kw_args["quay_password"] == "some-password"
    assert called_kw_args["pyxis_server"] == "pyxis-url.com"
    assert called_kw_args["pyxis_ssl_crtfile"] == "/path/to/file.crt"
    assert called_kw_args["pyxis_ssl_keyfile"] == "/path/to/file.key"
    assert called_kw_args["quay_api_token"] == "api_token"
    assert called_kw_args["quay_host"] == "quay-host.com"


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
        "--quay-host",
        "quay-host.com",
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
        "--quay-host",
        "quay-host.com",
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
        "--quay-host",
        "quay-host.com",
    ]

    with pytest.raises(ValueError, match="--quay-password must be specified"):
        remove_repo.remove_repositories_main(wrong_args)

    mock_remove_repositories.assert_not_called()


@mock.patch("pubtools._quay.remove_repo.QuayClient")
@mock.patch("pubtools._quay.remove_repo.QuayApiClient")
def test_run(
    mock_quay_api_client,
    mock_quay_client,
    hookspy,
    src_manifest_list,
    v2s1_manifest,
    fake_cert_key_paths,
    signer_wrapper_remove_signatures,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
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
    mock_delete_repo = mock.MagicMock()
    mock_quay_api_client.return_value.delete_repository = mock_delete_repo

    mock_get_repo_tags = mock.MagicMock()
    mock_get_repo_tags.return_value = {"tags": ["1", "2"]}
    mock_quay_client.return_value.get_repository_tags = mock_get_repo_tags

    # def get_manifest_side_effect(image, raw=False, media_type=False):
    #     if media_type == "application/vnd.docker.distribution.manifest.list.v2+json":
    #         content = src_manifest_list
    #     else:
    #         content = v2s1_manifest
    #     return json.dumps(content) if raw else content

    mock_quay_client.return_value.get_manifest.side_effect = GetManifestSideEffect(
        v2s1_manifest, src_manifest_list, call_limit=5
    )
    signer_wrapper_run_entry_point.return_value = [
        {
            "_id": 1,
            "manifest_digest": "sha256:3333333333",
            "reference": "some-registry.com/namespace/image:1",
            "sig_key_id": "key",
            "repository": "namespace/image",
        }
    ]
    remove_repo.remove_repositories_main(args)

    mock_quay_api_client.assert_called_once_with("some-token")
    signer_wrapper_remove_signatures.assert_called_once_with([1])
    mock_delete_repo.assert_called_once_with("quay-organization/namespace----image")

    assert hookspy == [
        ("task_start", {}),
        ("get_cert_key_paths", {"server_url": "pyxis-url.com"}),
        ("quay_repositories_removed", {"repository_ids": ["namespace/image"]}),
        ("task_stop", {"failed": False}),
    ]


@mock.patch("pubtools._quay.remove_repo.QuayClient")
@mock.patch("pubtools._quay.remove_repo.QuayApiClient")
def test_run_multiple_repos(
    mock_quay_api_client,
    mock_quay_client,
    hookspy,
    src_manifest_list,
    v2s1_manifest,
    fake_cert_key_paths,
    signer_wrapper_remove_signatures,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
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
    mock_delete_repo = mock.MagicMock()
    mock_quay_api_client.return_value.delete_repository = mock_delete_repo

    mock_get_repo_tags = mock.MagicMock()
    mock_get_repo_tags.return_value = {"tags": ["1", "2"]}
    mock_quay_client.return_value.get_repository_tags = mock_get_repo_tags

    # def get_manifest_side_effect(image, raw=False, media_type=False):
    #     if media_type == "application/vnd.docker.distribution.manifest.list.v2+json":
    #         content = src_manifest_list
    #     else:
    #         content = v2s1_manifest
    #     return json.dumps(content) if raw else content

    mock_quay_client.return_value.get_manifest.side_effect = GetManifestSideEffect(
        v2s1_manifest, src_manifest_list, call_limit=30
    )
    signer_wrapper_run_entry_point.return_value = [
        {
            "_id": 1,
            "manifest_digest": "sha256:3333333333",
            "reference": "some-registry.com/namespace/image2:1",
            "sig_key_id": "key",
            "repository": "namespace/image2",
        }
    ]

    remove_repo.remove_repositories_main(args)

    mock_quay_api_client.assert_called_once_with("some-token")
    signer_wrapper_remove_signatures.assert_called_once_with([1])
    assert mock_delete_repo.call_count == 2
    assert mock_delete_repo.call_args_list[0] == mock.call("quay-organization/namespace----image")
    assert mock_delete_repo.call_args_list[1] == mock.call("quay-organization/namespace----image2")
