import mock
import pytest

from pubtools._quay import clear_repo


@mock.patch("pubtools._quay.clear_repo.clear_repository")
def test_arg_constructor_required_args(mock_clear_repository):
    required_args = [
        "dummy",
        "--repository",
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
        "--pyxis-krb-principal",
        "some-principal",
    ]
    clear_repo.clear_repository_main(required_args)
    _, called_args = mock_clear_repository.call_args

    assert called_args["repository"] == "namespace/image"
    assert called_args["quay_org"] == "quay-organization"
    assert called_args["quay_user"] == "some-user"
    assert called_args["quay_password"] == "some-password"
    assert called_args["quay_api_token"] == "some-token"
    assert called_args["pyxis_server"] == "pyxis-url.com"
    assert called_args["pyxis_krb_principal"] == "some-principal"
    assert called_args["umb_topic"] == "VirtualTopic.eng.pub.quay_clear_repository"


@mock.patch.dict("os.environ", {"QUAY_API_TOKEN": "api_token", "QUAY_PASSWORD": "some-password"})
@mock.patch("pubtools._quay.clear_repo.clear_repository")
def test_arg_constructor_all_args(mock_clear_repository):
    all_args = [
        "dummy",
        "--repository",
        "namespace/image",
        "--quay-org",
        "quay-organization",
        "--quay-user",
        "some-user",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
        "--umb-url",
        "amqps://url:5672",
        "--umb-cert",
        "/path/to/file.crt",
        "--umb-client-key",
        "/path/to/umb.key",
        "--umb-ca-cert",
        "/path/to/ca_cert.crt",
        "--umb-topic",
        "VirtualTopic.eng.pub.clear_repo_new",
    ]
    clear_repo.clear_repository_main(all_args)
    _, called_args = mock_clear_repository.call_args

    assert called_args["repository"] == "namespace/image"
    assert called_args["quay_org"] == "quay-organization"
    assert called_args["quay_user"] == "some-user"
    assert called_args["quay_password"] == "some-password"
    assert called_args["pyxis_server"] == "pyxis-url.com"
    assert called_args["pyxis_krb_principal"] == "some-principal"
    assert called_args["send_umb_msg"] is True
    assert called_args["umb_urls"] == ["amqps://url:5671", "amqps://url:5672"]
    assert called_args["umb_cert"] == "/path/to/file.crt"
    assert called_args["umb_client_key"] == "/path/to/umb.key"
    assert called_args["umb_ca_cert"] == "/path/to/ca_cert.crt"
    assert called_args["quay_api_token"] == "api_token"
    assert called_args["umb_topic"] == "VirtualTopic.eng.pub.clear_repo_new"


@mock.patch("pubtools._quay.clear_repo.clear_repository")
def test_args_missing_repository(mock_clear_repository):
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
        "--pyxis-krb-principal",
        "some-principal",
    ]

    with pytest.raises(SystemExit) as system_error:
        clear_repo.clear_repository_main(wrong_args)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2
    mock_clear_repository.assert_not_called()


@mock.patch("pubtools._quay.clear_repo.clear_repository")
def test_args_missing_api_token(mock_clear_repository):
    wrong_args = [
        "dummy",
        "--repository",
        "namespace/image",
        "--quay-org",
        "quay-organization",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
    ]

    with pytest.raises(ValueError, match="--quay-api-token must be specified"):
        clear_repo.clear_repository_main(wrong_args)

    mock_clear_repository.assert_not_called()


@mock.patch("pubtools._quay.clear_repo.clear_repository")
def test_args_missing_quay_password(mock_clear_repository):
    wrong_args = [
        "dummy",
        "--repository",
        "namespace/image",
        "--quay-org",
        "quay-organization",
        "--quay-user",
        "some-user",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
    ]

    with pytest.raises(ValueError, match="--quay-password must be specified"):
        clear_repo.clear_repository_main(wrong_args)

    mock_clear_repository.assert_not_called()


@mock.patch("pubtools._quay.clear_repo.send_umb_message")
@mock.patch("pubtools._quay.clear_repo.QuayApiClient")
def test_args_incorrect_repo(mock_quay_api_client, mock_send_umb_message):
    wrong_args = [
        "dummy",
        "--repository",
        "namespace---image",
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
        "--pyxis-krb-principal",
        "some-principal",
    ]

    with pytest.raises(ValueError, match="Provided repository must have format <namespace>/<repo>"):
        clear_repo.clear_repository_main(wrong_args)
    wrong_args[2] == "/namespaceimage"
    with pytest.raises(ValueError, match="Provided repository must have format <namespace>/<repo>"):
        clear_repo.clear_repository_main(wrong_args)
    wrong_args[2] == "namespaceimage/"
    with pytest.raises(ValueError, match="Provided repository must have format <namespace>/<repo>"):
        clear_repo.clear_repository_main(wrong_args)

    mock_quay_api_client.assert_not_called()
    mock_send_umb_message.assert_not_called()


@mock.patch("pubtools._quay.clear_repo.send_umb_message")
@mock.patch("pubtools._quay.clear_repo.QuayApiClient")
def test_args_missing_umb_url(mock_quay_api_client, mock_send_umb_message):
    wrong_args = [
        "dummy",
        "--repository",
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
        "--pyxis-krb-principal",
        "some-principal",
        "--send-umb-msg",
        "--umb-cert",
        "/path/to/file.crt",
    ]

    with pytest.raises(ValueError, match="UMB URL must be specified.*"):
        clear_repo.clear_repository_main(wrong_args)

    mock_quay_api_client.assert_not_called()
    mock_send_umb_message.assert_not_called()


@mock.patch("pubtools._quay.clear_repo.send_umb_message")
@mock.patch("pubtools._quay.clear_repo.QuayApiClient")
def test_args_missing_umb_cert(mock_quay_api_client, mock_send_umb_message):
    wrong_args = [
        "dummy",
        "--repository",
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
        "--pyxis-krb-principal",
        "some-principal",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
    ]

    with pytest.raises(ValueError, match="A path to a client certificate.*"):
        clear_repo.clear_repository_main(wrong_args)

    mock_quay_api_client.assert_not_called()
    mock_send_umb_message.assert_not_called()


@mock.patch("pubtools._quay.clear_repo.untag_images")
@mock.patch("pubtools._quay.clear_repo.SignatureRemover")
@mock.patch("pubtools._quay.clear_repo.send_umb_message")
@mock.patch("pubtools._quay.clear_repo.QuayApiClient")
def test_run(
    mock_quay_api_client, mock_send_umb_message, mock_signature_remover, mock_untag_images
):
    args = [
        "dummy",
        "--repository",
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
        "--pyxis-krb-principal",
        "some-principal",
    ]
    mock_get_repo_data = mock.MagicMock()
    mock_get_repo_data.return_value = {"tags": {"1": {"some": " data"}, "2": {"some": "data"}}}
    mock_quay_api_client.return_value.get_repository_data = mock_get_repo_data
    mock_set_quay_api_client = mock.MagicMock()
    mock_remove_repository_signatures = mock.MagicMock()
    mock_signature_remover.return_value.set_quay_api_client = mock_set_quay_api_client
    mock_signature_remover.return_value.remove_repository_signatures = (
        mock_remove_repository_signatures
    )

    clear_repo.clear_repository_main(args)

    mock_quay_api_client.assert_called_once_with("some-token")
    mock_signature_remover.assert_called_once_with(
        quay_user="some-user", quay_password="some-password"
    )
    mock_set_quay_api_client.assert_called_once_with(mock_quay_api_client.return_value)
    mock_remove_repository_signatures.assert_called_once_with(
        "namespace/image", "quay-organization", "pyxis-url.com", "some-principal", None
    )
    mock_get_repo_data.assert_called_once_with("quay-organization/namespace----image")
    mock_untag_images.assert_called_once_with(
        [
            "quay.io/quay-organization/namespace----image:1",
            "quay.io/quay-organization/namespace----image:2",
        ],
        "some-token",
        remove_last=True,
        quay_user="some-user",
        quay_password="some-password",
        send_umb_msg=False,
        umb_urls=None,
        umb_cert=None,
        umb_client_key=None,
        umb_ca_cert=None,
    )
    mock_send_umb_message.assert_not_called()


@mock.patch("pubtools._quay.clear_repo.untag_images")
@mock.patch("pubtools._quay.clear_repo.SignatureRemover")
@mock.patch("pubtools._quay.clear_repo.send_umb_message")
@mock.patch("pubtools._quay.clear_repo.QuayApiClient")
def test_send_umb_message(
    mock_quay_api_client, mock_send_umb_message, mock_signature_remover, mock_untag_images
):
    args = [
        "dummy",
        "--repository",
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
        "--pyxis-krb-principal",
        "some-principal",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
        "--umb-cert",
        "/path/to/file.crt",
        "--umb-client-key",
        "/path/to/umb.key",
        "--umb-ca-cert",
        "/path/to/ca_cert.crt",
        "--umb-topic",
        "VirtualTopic.eng.pub.clear_repo_new",
    ]
    mock_get_repo_data = mock.MagicMock()
    mock_get_repo_data.return_value = {"tags": {"1": {"some": " data"}, "2": {"some": "data"}}}
    mock_quay_api_client.return_value.get_repository_data = mock_get_repo_data
    mock_set_quay_api_client = mock.MagicMock()
    mock_remove_repository_signatures = mock.MagicMock()
    mock_signature_remover.return_value.set_quay_api_client = mock_set_quay_api_client
    mock_signature_remover.return_value.remove_repository_signatures = (
        mock_remove_repository_signatures
    )
    clear_repo.clear_repository_main(args)

    mock_set_quay_api_client.assert_called_once_with(mock_quay_api_client.return_value)
    mock_remove_repository_signatures.assert_called_once_with(
        "namespace/image", "quay-organization", "pyxis-url.com", "some-principal", None
    )
    mock_get_repo_data.assert_called_once_with("quay-organization/namespace----image")
    mock_untag_images.assert_called_once_with(
        [
            "quay.io/quay-organization/namespace----image:1",
            "quay.io/quay-organization/namespace----image:2",
        ],
        "some-token",
        remove_last=True,
        quay_user="some-user",
        quay_password="some-password",
        send_umb_msg=True,
        umb_urls=["amqps://url:5671"],
        umb_cert="/path/to/file.crt",
        umb_client_key="/path/to/umb.key",
        umb_ca_cert="/path/to/ca_cert.crt",
    )
    mock_send_umb_message.assert_called_once_with(
        ["amqps://url:5671"],
        {"cleared_repository": "namespace/image"},
        "/path/to/file.crt",
        "VirtualTopic.eng.pub.clear_repo_new",
        client_key="/path/to/umb.key",
        ca_cert="/path/to/ca_cert.crt",
    )
