import logging
import mock
import pytest
import requests_mock
import requests

from pubtools._quay import manifest_claims_handler
from .utils.misc import sort_dictionary_sortable_values, compare_logs

# flake8: noqa: E501


@mock.patch("pubtools._quay.manifest_claims_handler.proton.SSLDomain")
def test_init(mock_ssl_domain):
    hub = mock.MagicMock()
    message_sender_callback = lambda messages: hub.worker.umb_send_manifest_claim_messages(
        "1", messages
    )
    mock_set_credentials = mock.MagicMock()
    mock_set_trusted_ca_db = mock.MagicMock()
    mock_set_peer_authentication = mock.MagicMock()
    mock_ssl_domain.return_value.set_credentials = mock_set_credentials
    mock_ssl_domain.return_value.set_trusted_ca_db = mock_set_trusted_ca_db
    mock_ssl_domain.return_value.set_peer_authentication = mock_set_peer_authentication

    claim_messages = [
        {
            "sig_key_id": "key1",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "asdasdasd-77bc-4222-ad6a-89f508f02d75",
            "manifest_digest": "sha256:f4f4f4f",
            "repo": "some-dest-repo",
            "image_name": "image",
            "docker_reference": "registry.com/image:1",
            "created": "2021-03-19T14:45:23.128632Z",
        },
        {
            "sig_key_id": "key2",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "7ed1d8fb-77bc-4222-ad6a-89f508f02d75",
            "manifest_digest": "sha256:f4f4f4f",
            "repo": "some-dest-repo",
            "image_name": "image",
            "docker_reference": "registry.com/image:1",
            "created": "2021-03-19T14:45:23.128632Z",
        },
    ]
    handler = manifest_claims_handler.ManifestClaimsHandler(
        ["umb-url1.com", "umb_url2.com"],
        "queue://Consumer.msg-producer-pub.some-address",
        claim_messages,
        "/etc/pub/umb-pub-cert-key.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        600,
        100,
        3,
        message_sender_callback,
    )

    assert handler.umb_urls == ["umb-url1.com", "umb_url2.com"]
    assert handler.radas_address == "queue://Consumer.msg-producer-pub.some-address"
    assert handler.claim_messages == claim_messages
    assert handler.timeout == 600
    assert handler.throttle == 100
    assert handler.retry == 3
    assert handler.message_sender_callback == message_sender_callback
    assert handler.to_send == claim_messages
    assert handler.id_msg_map == {
        "asdasdasd-77bc-4222-ad6a-89f508f02d75": claim_messages[0],
        "7ed1d8fb-77bc-4222-ad6a-89f508f02d75": claim_messages[1],
    }
    mock_ssl_domain.assert_called_once()
    mock_set_credentials.assert_called_once()
    mock_set_trusted_ca_db.assert_called_once()
    mock_set_peer_authentication.assert_called_once()


@mock.patch("pubtools._quay.manifest_claims_handler.proton.SSLDomain")
def test_on_start(mock_ssl_domain):
    hub = mock.MagicMock()
    message_sender_callback = lambda messages: hub.worker.umb_send_manifest_claim_messages(
        "1", messages
    )
    mock_connect = mock.MagicMock()
    mock_connect.return_value = "some-connection"
    mock_create_receiver = mock.MagicMock()
    mock_create_receiver.return_value = "some-receiver"
    mock_schedule = mock.MagicMock()
    mock_schedule.return_value = "some-timer-task"
    mock_container = mock.MagicMock()
    mock_container.connect = mock_connect
    mock_container.create_receiver = mock_create_receiver
    mock_container.schedule = mock_schedule
    mock_event = mock.MagicMock()
    mock_event.container = mock_container

    handler = manifest_claims_handler.ManifestClaimsHandler(
        ["umb-url1.com", "umb_url2.com"],
        "queue://Consumer.msg-producer-pub.some-address",
        [{"request_id": "1"}, {"request_id": "2"}],
        "/etc/pub/umb-pub-cert-key.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        600,
        100,
        3,
        message_sender_callback,
    )

    handler.on_start(mock_event)
    mock_connect.assert_called_once_with(
        urls=["umb-url1.com", "umb_url2.com"],
        ssl_domain=mock_ssl_domain.return_value,
        sasl_enabled=False,
    )
    mock_create_receiver.assert_called_once_with(
        "some-connection", "queue://Consumer.msg-producer-pub.some-address"
    )
    assert handler.receiver == "some-receiver"
    mock_schedule.assert_called_once_with(600, handler)
    assert handler.timer_task == "some-timer-task"


@mock.patch("pubtools._quay.manifest_claims_handler.ManifestClaimsHandler._send_message")
@mock.patch("pubtools._quay.manifest_claims_handler.monotonic.monotonic")
@mock.patch("pubtools._quay.manifest_claims_handler.proton.SSLDomain")
def test_on_timer_task_no_failures(mock_ssl_domain, mock_monotonic, mock_send_message):
    hub = mock.MagicMock()
    message_sender_callback = lambda messages: hub.worker.umb_send_manifest_claim_messages(
        "1", messages
    )

    mock_schedule = mock.MagicMock()
    mock_schedule.return_value = "some-timer-task"
    mock_container = mock.MagicMock()
    mock_container.schedule = mock_schedule
    mock_event = mock.MagicMock()
    mock_event.container = mock_container
    mock_monotonic.side_effect = [700, 702]

    handler = manifest_claims_handler.ManifestClaimsHandler(
        ["umb-url1.com", "umb_url2.com"],
        "queue://Consumer.msg-producer-pub.some-address",
        [{"request_id": "1"}, {"request_id": "2"}],
        "/etc/pub/umb-pub-cert-key.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        600,
        100,
        3,
        message_sender_callback,
    )
    handler.connected = "yes"
    handler.awaiting_response = {"1": 500, "2": 10}
    handler.to_send = []

    handler.on_timer_task(mock_event)

    assert mock_monotonic.call_count == 2
    assert handler.retry_count == {"2": 1}
    assert handler.to_send == [{"request_id": "2"}]
    assert handler.awaiting_response == {"1": 500}
    mock_send_message.assert_called_once_with(1)
    mock_schedule.assert_called_once()
    assert handler.timer_task == "some-timer-task"


@mock.patch("pubtools._quay.manifest_claims_handler.ManifestClaimsHandler._send_message")
@mock.patch("pubtools._quay.manifest_claims_handler.monotonic.monotonic")
@mock.patch("pubtools._quay.manifest_claims_handler.proton.SSLDomain")
def test_on_timer_task_retry_limit_reached(
    mock_ssl_domain, mock_monotonic, mock_send_message, caplog
):
    hub = mock.MagicMock()
    message_sender_callback = lambda messages: hub.worker.umb_send_manifest_claim_messages(
        "1", messages
    )

    mock_stop = mock.MagicMock()
    mock_schedule = mock.MagicMock()
    mock_container = mock.MagicMock()
    mock_container.schedule = mock_schedule
    mock_container.stop = mock_stop
    mock_event = mock.MagicMock()
    mock_event.container = mock_container
    mock_monotonic.side_effect = [700, 702]

    handler = manifest_claims_handler.ManifestClaimsHandler(
        ["umb-url1.com", "umb_url2.com"],
        "queue://Consumer.msg-producer-pub.some-address",
        [{"request_id": "1"}, {"request_id": "2"}],
        "/etc/pub/umb-pub-cert-key.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        600,
        100,
        3,
        message_sender_callback,
    )
    handler.connected = "yes"
    handler.awaiting_response = {"1": 500, "2": 10}
    handler.to_send = []
    handler.retry_count["2"] = 3

    with pytest.raises(manifest_claims_handler.MessageHandlerTimeoutException):
        handler.on_timer_task(mock_event)

    assert mock_monotonic.call_count == 2
    mock_send_message.assert_not_called()
    mock_schedule.assert_not_called()
    mock_stop.assert_called_once_with()

    expected_logs = ["Stopping message event loop due to timeout.*"]
    compare_logs(caplog, expected_logs)


@mock.patch("pubtools._quay.manifest_claims_handler.proton.SSLDomain")
def test_on_timer_task_not_connected(mock_ssl_domain, caplog):
    hub = mock.MagicMock()
    message_sender_callback = lambda messages: hub.worker.umb_send_manifest_claim_messages(
        "1", messages
    )
    mock_stop = mock.MagicMock()
    mock_schedule = mock.MagicMock()
    mock_container = mock.MagicMock()
    mock_container.stop = mock_stop
    mock_container.schedule = mock_schedule
    mock_event = mock.MagicMock()
    mock_event.container = mock_container

    handler = manifest_claims_handler.ManifestClaimsHandler(
        ["umb-url1.com", "umb_url2.com"],
        "queue://Consumer.msg-producer-pub.some-address",
        [{"request_id": "1"}, {"request_id": "2"}],
        "/etc/pub/umb-pub-cert-key.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        600,
        100,
        3,
        message_sender_callback,
    )
    handler.connected = False

    with pytest.raises(manifest_claims_handler.MessageHandlerTimeoutException):
        handler.on_timer_task(mock_event)

    mock_stop.assert_called_once_with()
    mock_schedule.assert_not_called()

    expected_logs = ["Couldn't connect to brokers.*"]
    compare_logs(caplog, expected_logs)


@mock.patch("pubtools._quay.manifest_claims_handler.ManifestClaimsHandler._send_message")
@mock.patch("pubtools._quay.manifest_claims_handler.proton.SSLDomain")
def test_on_link_opened(mock_ssl_domain, mock_send_message, caplog):
    hub = mock.MagicMock()
    message_sender_callback = lambda messages: hub.worker.umb_send_manifest_claim_messages(
        "1", messages
    )

    mock_schedule = mock.MagicMock()
    mock_schedule.return_value = "new-timer-task"
    mock_container = mock.MagicMock()
    mock_container.schedule = mock_schedule
    mock_receiver = mock.MagicMock()
    mock_event = mock.MagicMock()
    mock_event.container = mock_container
    mock_event.receiver = mock_receiver

    mock_cancel = mock.MagicMock()
    mock_timer_task = mock.MagicMock()
    mock_timer_task.cancel = mock_cancel

    handler = manifest_claims_handler.ManifestClaimsHandler(
        ["umb-url1.com", "umb_url2.com"],
        "queue://Consumer.msg-producer-pub.some-address",
        [{"request_id": "1"}, {"request_id": "2"}],
        "/etc/pub/umb-pub-cert-key.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        600,
        100,
        3,
        message_sender_callback,
    )
    handler.receiver = mock_receiver
    handler.timer_task = mock_timer_task

    handler.on_link_opened(mock_event)

    mock_cancel.assert_called_once_with()
    assert handler.connected is True
    mock_send_message.assert_called_once_with()
    mock_schedule.assert_called_once()
    assert handler.timer_task == "new-timer-task"
    expected_logs = []
    compare_logs(caplog, expected_logs)


@mock.patch("pubtools._quay.manifest_claims_handler.ManifestClaimsHandler._send_message")
@mock.patch("pubtools._quay.manifest_claims_handler.proton.SSLDomain")
def test_on_link_opened_unknown_event(mock_ssl_domain, mock_send_message, caplog):
    hub = mock.MagicMock()
    message_sender_callback = lambda messages: hub.worker.umb_send_manifest_claim_messages(
        "1", messages
    )

    mock_receiver = mock.MagicMock()
    mock_event = mock.MagicMock()
    mock_event.receiver = mock_receiver
    mock_cancel = mock.MagicMock()
    mock_timer_task = mock.MagicMock()
    mock_timer_task.cancel = mock_cancel

    handler = manifest_claims_handler.ManifestClaimsHandler(
        ["umb-url1.com", "umb_url2.com"],
        "queue://Consumer.msg-producer-pub.some-address",
        [{"request_id": "1"}, {"request_id": "2"}],
        "/etc/pub/umb-pub-cert-key.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        600,
        100,
        3,
        message_sender_callback,
    )
    handler.receiver = "other-receiver"
    handler.timer_task = mock_timer_task

    handler.on_link_opened(mock_event)

    mock_cancel.assert_not_called()
    assert handler.connected is False
    expected_logs = ["Unexpected on_link_opened event"]
    compare_logs(caplog, expected_logs)


@mock.patch("pubtools._quay.manifest_claims_handler.ManifestClaimsHandler._send_message")
@mock.patch("pubtools._quay.manifest_claims_handler.proton.SSLDomain")
def test_on_message_last_one(mock_ssl_domain, mock_send_message, caplog):
    caplog.set_level(logging.INFO)
    hub = mock.MagicMock()
    message_sender_callback = lambda messages: hub.worker.umb_send_manifest_claim_messages(
        "1", messages
    )

    mock_message = mock.MagicMock()
    mock_message.body = '{"msg": {"request_id": "1"}}'
    mock_close = mock.MagicMock()
    mock_connection = mock.MagicMock()
    mock_connection.close = mock_close
    mock_event = mock.MagicMock()
    mock_event.connection = mock_connection
    mock_event.message = mock_message

    mock_receiver_close = mock.MagicMock()
    mock_receiver = mock.MagicMock()
    mock_receiver.close = mock_receiver_close

    mock_cancel = mock.MagicMock()
    mock_timer_task = mock.MagicMock()
    mock_timer_task.cancel = mock_cancel

    handler = manifest_claims_handler.ManifestClaimsHandler(
        ["umb-url1.com", "umb_url2.com"],
        "queue://Consumer.msg-producer-pub.some-address",
        [],
        "/etc/pub/umb-pub-cert-key.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        600,
        100,
        3,
        message_sender_callback,
    )
    handler.awaiting_response = {"1": "1"}
    handler.receiver = mock_receiver
    handler.timer_task = mock_timer_task

    handler.on_message(mock_event)

    assert handler.awaiting_response == {}
    assert handler.received_messages == [{"request_id": "1"}]
    mock_receiver_close.assert_called_once_with()
    mock_close.assert_called_once_with()
    mock_cancel.assert_called_once_with()
    expected_logs = [
        "Received signing response.*",
        "All requests satisfied, closing connection...",
        "Connection closed.",
    ]
    compare_logs(caplog, expected_logs)


@mock.patch("pubtools._quay.manifest_claims_handler.ManifestClaimsHandler._send_message")
@mock.patch("pubtools._quay.manifest_claims_handler.proton.SSLDomain")
def test_on_message_not_last_one(mock_ssl_domain, mock_send_message, caplog):
    caplog.set_level(logging.INFO)
    hub = mock.MagicMock()
    message_sender_callback = lambda messages: hub.worker.umb_send_manifest_claim_messages(
        "1", messages
    )

    mock_message = mock.MagicMock()
    mock_message.body = '{"msg": {"request_id": "1"}}'
    mock_close = mock.MagicMock()
    mock_connection = mock.MagicMock()
    mock_connection.close = mock_close
    mock_event = mock.MagicMock()
    mock_event.connection = mock_connection
    mock_event.message = mock_message

    mock_receiver_close = mock.MagicMock()
    mock_receiver = mock.MagicMock()
    mock_receiver.close = mock_receiver_close

    mock_cancel = mock.MagicMock()
    mock_timer_task = mock.MagicMock()
    mock_timer_task.cancel = mock_cancel

    handler = manifest_claims_handler.ManifestClaimsHandler(
        ["umb-url1.com", "umb_url2.com"],
        "queue://Consumer.msg-producer-pub.some-address",
        [],
        "/etc/pub/umb-pub-cert-key.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        600,
        100,
        3,
        message_sender_callback,
    )
    handler.awaiting_response = {"1": "1", "2": "2"}
    handler.receiver = mock_receiver
    handler.timer_task = mock_timer_task

    handler.on_message(mock_event)

    assert handler.awaiting_response == {"2": "2"}
    assert handler.received_messages == [{"request_id": "1"}]
    mock_receiver_close.assert_not_called()
    mock_close.assert_not_called()
    mock_cancel.assert_not_called()
    expected_logs = [
        "Received signing response.*",
    ]
    compare_logs(caplog, expected_logs)


@mock.patch("pubtools._quay.manifest_claims_handler.ManifestClaimsHandler._send_message")
@mock.patch("pubtools._quay.manifest_claims_handler.proton.SSLDomain")
def test_on_message_unknown_message(mock_ssl_domain, mock_send_message, caplog):
    caplog.set_level(logging.DEBUG, logger="PubLogger")
    hub = mock.MagicMock()
    message_sender_callback = lambda messages: hub.worker.umb_send_manifest_claim_messages(
        "1", messages
    )

    mock_message = mock.MagicMock()
    mock_message.body = '{"msg": {"request_id": "3"}}'
    mock_close = mock.MagicMock()
    mock_connection = mock.MagicMock()
    mock_connection.close = mock_close
    mock_event = mock.MagicMock()
    mock_event.connection = mock_connection
    mock_event.message = mock_message

    mock_receiver_close = mock.MagicMock()
    mock_receiver = mock.MagicMock()
    mock_receiver.close = mock_receiver_close

    mock_cancel = mock.MagicMock()
    mock_timer_task = mock.MagicMock()
    mock_timer_task.cancel = mock_cancel

    handler = manifest_claims_handler.ManifestClaimsHandler(
        ["umb-url1.com", "umb_url2.com"],
        "queue://Consumer.msg-producer-pub.some-address",
        [],
        "/etc/pub/umb-pub-cert-key.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        600,
        100,
        3,
        message_sender_callback,
    )
    handler.awaiting_response = {"1": "1", "2": "2"}
    handler.receiver = mock_receiver
    handler.timer_task = mock_timer_task

    handler.on_message(mock_event)

    assert handler.awaiting_response == {"1": "1", "2": "2"}
    assert handler.received_messages == []
    mock_receiver_close.assert_not_called()
    mock_close.assert_not_called()
    mock_cancel.assert_not_called()
    expected_logs = [
        "Ignored signing response.*",
    ]
    compare_logs(caplog, expected_logs)


@mock.patch("pubtools._quay.manifest_claims_handler.monotonic.monotonic")
@mock.patch("pubtools._quay.manifest_claims_handler.proton.SSLDomain")
def test_send_message(mock_ssl_domain, mock_monotonic):
    mock_monotonic.side_effect = [10, 20]

    mock_umb_send_manifest_claim_messages = mock.MagicMock()
    mock_worker = mock.MagicMock()
    mock_worker.umb_send_manifest_claim_messages = mock_umb_send_manifest_claim_messages
    hub = mock.MagicMock()
    hub.worker = mock_worker

    message_sender_callback = lambda messages: hub.worker.umb_send_manifest_claim_messages(
        "1", messages
    )

    handler = manifest_claims_handler.ManifestClaimsHandler(
        ["umb-url1.com", "umb_url2.com"],
        "queue://Consumer.msg-producer-pub.some-address",
        [{"request_id": "1"}, {"request_id": "2"}],
        "/etc/pub/umb-pub-cert-key.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        600,
        100,
        3,
        message_sender_callback,
    )
    handler._send_message()

    mock_umb_send_manifest_claim_messages.assert_called_once_with(
        "1", [{"request_id": "1"}, {"request_id": "2"}]
    )
    assert handler.to_send == []
    assert handler.awaiting_response == {"1": 10, "2": 20}


@mock.patch("pubtools._quay.manifest_claims_handler.proton.SSLDomain")
def test_events_logs(mock_ssl_domain, caplog):
    caplog.set_level(logging.DEBUG, logger="PubLogger")
    hub = mock.MagicMock()
    event = mock.MagicMock()

    message_sender_callback = lambda messages: hub.worker.umb_send_manifest_claim_messages(
        "1", messages
    )

    handler = manifest_claims_handler.ManifestClaimsHandler(
        ["umb-url1.com", "umb_url2.com"],
        "queue://Consumer.msg-producer-pub.some-address",
        [{"request_id": "1"}, {"request_id": "2"}],
        "/etc/pub/umb-pub-cert-key.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        600,
        100,
        3,
        message_sender_callback,
    )
    handler.on_connection_closed(event)
    handler.on_session_closed(event)
    handler.on_link_closed(event)
    handler.on_connection_closing(event)
    handler.on_session_closing(event)
    handler.on_link_closing(event)
    handler.on_disconnected(event)

    expected_logs = [
        "Messaging event: connection_closed",
        "Messaging event: session_closed",
        "Messaging event: link_closed",
        "Messaging event: connection_closing",
        "Messaging event: session_closing",
        "Messaging event: link_closing",
        "Messaging event: disconnected",
    ]
    compare_logs(caplog, expected_logs)
