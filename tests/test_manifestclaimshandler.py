import itertools
import json
import logging
import os
import uuid

import pytest
from hamcrest import assert_that, contains_string, equal_to
from proton.reactor import Container

from pubtools._quay.manifest_claims_handler import (
    ManifestClaimsHandler,
    MessageHandlerTimeoutException,
    AMQPEndpointError,
    _ManifestClaimsRunner,
    UMBSettings,
)

try:
    from unittest.mock import Mock, patch, MagicMock
except ImportError:
    from mock import Mock, patch, MagicMock

DEFAULT_AMQPS_URL = "amqps://{hostname}:{port}".format(hostname="localhost", port=5672)

HERE = os.path.dirname(__file__)
UMB_CERT_DIR = os.path.normpath(os.path.join(HERE, "../", "integration", "utils", "umb_certs"))

ROOT_CA = os.path.join(UMB_CERT_DIR, "rootCA.pem")

PUB_UMB_CLIENT_CERT = os.path.join(UMB_CERT_DIR, "pub-cert-key.pem")

TEST_TOPIC = "tests.manifestclaimshandler.TestTopic"

# flake8: noqa: D101, D107, D102, D205, D400, D403


@pytest.fixture
def debug_logs(caplog):
    caplog.set_level(logging.DEBUG)
    return caplog


@pytest.fixture
def umb_client_settings():
    return UMBSettings(
        [DEFAULT_AMQPS_URL],
        radas_address=TEST_TOPIC,
        pub_cert=PUB_UMB_CLIENT_CERT,
        ca_cert=ROOT_CA,
        signing_timeout=5,
        signing_throttle=10,
        signing_retry=3,
    )


@pytest.fixture
def handler(umb_client_settings):
    """Yields a ManifestClaimsHandler instance with no messages."""
    with patch("proton.SSLDomain"):
        yield ManifestClaimsHandler(umb_client_settings, [], message_sender_callback=lambda: None)


@pytest.fixture
def runner(umb_client_settings):
    return _ManifestClaimsRunner(umb_client_settings, [], lambda: None)


@pytest.mark.parametrize(
    "event_name",
    [
        "connection_closing",
        "connection_closed",
        "connection_error",
        "session_closing",
        "session_closed",
        "session_error",
        "link_closing",
        "link_closed",
        "link_error",
        "transport_error",
        "disconnected",
    ],
)
def test_logs_event(handler, event_name, debug_logs):
    """ManifestClaimsHandler logs a message when various events are received."""
    event = Mock()
    handler._endpoint_error = MagicMock()

    callback = getattr(handler, "on_%s" % event_name)
    # It should execute successfully.
    callback(event)

    logs = debug_logs.text

    # It should log the name of the event which occurred.
    assert_that(logs, contains_string("Messaging event: {0}".format(event_name)))


def test_logs_unexpected_link_opened(handler, caplog):
    """ManifestClaimsHandler logs a message when on_link_opened
    event is received with an unexpected receiver."""

    event = Mock(receiver=object())

    # It should execute successfully.
    handler.on_link_opened(event)

    logs = caplog.text

    # It should warn due to event with unexpected receiver.
    assert "Unexpected on_link_opened event" in logs


def test_logs_ignored_message(handler, debug_logs):
    """ManifestClaimsHandler logs a message when receiving a radas message
    which can't be linked to a request within the current task."""
    message_body = json.dumps({"msg": {"request_id": "abcdef"}})
    event = Mock(message=Mock(body=message_body))

    # It should execute successfully.
    handler.on_message(event)

    logs = debug_logs.text

    # It should mention that we got a message, but it's not relevant
    # to our handler.
    assert "Ignored signing response: abcdef" in logs


@patch("monotonic.monotonic")
def test_awaiting_response_time_out(fake_timer, handler, caplog):
    handler.timeout = 10
    handler.connected = True
    handler.awaiting_response = {"request_id1": 43190}
    handler.retry_count = {"request_id1": 3}
    # assume it's been tried three times
    fake_timer.return_value = 43210

    event = MagicMock(container=MagicMock(spec=Container))

    with pytest.raises(MessageHandlerTimeoutException):
        handler.on_timer_task(event)

    event.container.stop.assert_called_once()

    logs = caplog.text

    assert "Stopping message event loop due to timeout request_id1" in logs


@patch("monotonic.monotonic")
def test_awaiting_response_retry(fake_timer, handler, caplog):
    handler.timeout = 10
    handler.throttle = 5
    handler.awaiting_response = {"request_id1": 43190}
    handler.retry_count = {"request_id1": 2}
    handler.id_msg_map = {"request_id1": {"request_id": "request_id1", "msg": "message1"}}
    handler.to_send = []
    handler.connected = True
    handler.message_sender_callback = Mock()
    for i in range(2, 11):
        handler.to_send.append({"request_id": "request_id%s" % i, "msg": "message%s" % i})
    # assume it's been tried twice
    fake_timer.side_effect = [43210 + i for i in range(6)]

    event = Mock()

    handler.on_timer_task(event)

    # 5 more messages in queue should be sent
    assert len(handler.awaiting_response) == 5
    # there should be 4+1 message left
    assert len(handler.to_send) == 5
    # the last one is the one timeouted
    assert handler.to_send[-1] == {"request_id": "request_id1", "msg": "message1"}

    assert event.container.schedule.called

    logs = caplog.text
    assert "Didn't receive response in 10 for request request_id1, will retry [3/3]" in logs


def test_cannot_connect_umb_timeout(handler, caplog):
    event = Mock()

    with pytest.raises(MessageHandlerTimeoutException):
        handler.on_timer_task(event)

    logs = caplog.text

    assert "Couldn't connect to brokers after {0} seconds".format(handler.timeout) in logs


def test_non_fatal_transport_error(handler):
    condition = MagicMock(name="Fake Name", description="Fake Description")
    endpoint = MagicMock(name="Transport", condition=condition)
    event = MagicMock(transport=endpoint)

    handler._endpoint_error_if_unhandled = MagicMock()
    handler._on_error = MagicMock()
    handler.on_transport_error(event)
    handler._endpoint_error_if_unhandled.assert_called_once_with(event, endpoint)
    handler._on_error.assert_not_called()


def test_fatal_transport_error(handler):
    condition = MagicMock(description="local-idle-timeout expired")
    # Passing name as a keyword argument to MagicMock constructor
    # conflicts with the MagicMock#name field, and produces something
    # like <MagicMock name="amqp:resource-limit-exceeded" id=<some integer>
    # when name is accessed again. Overwrite name entirely here.
    condition.name = "amqp:resource-limit-exceeded"
    endpoint = MagicMock(name="Transport", condition=condition)
    event = MagicMock(transport=endpoint)

    handler._on_error = MagicMock()
    handler.on_transport_error(event)
    handler._on_error.assert_called_once()


@pytest.mark.parametrize(
    "endpoint_name,condition",
    itertools.product(("connection", "session", "link"), (("FakeName", "FakeDescription"), None)),
)
def test_other_endpoint_errors(endpoint_name, condition, handler, debug_logs):
    if condition is not None:
        name, description = condition
        condition = MagicMock(description=description)
        setattr(condition, "name", name)

    endpoint = MagicMock(name=endpoint_name, condition=condition, remote_condition=condition)
    endpoint.__class__.__name__ = endpoint_name.capitalize()

    event = MagicMock()
    setattr(event, endpoint_name, endpoint)

    handler._on_error = MagicMock()
    method = getattr(handler, "on_{endpoint}_error".format(endpoint=endpoint_name))
    method(event)
    handler._on_error.assert_called_once()

    logs = debug_logs.text
    label = condition.name if condition is not None else "Unknown"
    if condition is not None:
        description = condition.description
    else:
        description = "No error description provided."

    expected_error = AMQPEndpointError(
        endpoint_name=endpoint_name.capitalize(),
        error_label=label,
        description=description,
    )
    assert_that(logs, contains_string(str(expected_error)))


def test_manifest_claims_runner_on_error_restarts(runner, debug_logs):
    claims = [{"request_id": uuid.uuid4(), "msg": {"field": "value"}}]

    uid = uuid.uuid4()
    received = {uid: {"request_id": uid, "msg": {"field": "value"}}}

    runner._claim_messages = claims
    runner._received_messages = received
    runner._run = MagicMock()
    runtime_error_message = "Runtime error message"
    exception = RuntimeError(runtime_error_message)

    runner.on_error(exception)

    assert_that(runner._retry_attempts, equal_to(1))
    runner._run.assert_called_once_with(claims)
    logs = debug_logs.text
    check_strings = [
        "Error in message handler: {0}".format(exception),
        "Restarting message handler for {0} remaining claims (retry {1}/{2})".format(
            len(claims), runner._retry_attempts, runner._maximum_retries
        ),
    ]
    for string in check_strings:
        assert_that(logs, contains_string(string))


def test_manifest_claims_runner_on_error_no_restart(runner, debug_logs):
    claims = [{"request_id": uuid.uuid4(), "msg": {"field": "value"}}]

    received = dict((m["request_id"], m) for m in claims)

    runner._claim_messages = claims
    runner._received_messages = received
    runner._run = MagicMock()

    runtime_error_message = "Runtime error message"
    exception = RuntimeError(runtime_error_message)

    runner.on_error(exception)

    assert_that(runner._retry_attempts, equal_to(0))
    runner._run.assert_not_called()

    logs = debug_logs.text
    check_strings = [
        "Error in message handler: {0}".format(exception),
        "No claims missing responses. Restart not required.",
    ]
    for string in check_strings:
        assert_that(logs, contains_string(string))


def test_manifest_claims_runner_no_more_retries(runner, debug_logs):
    runner._run = MagicMock()
    runner._retry_attempts = runner._maximum_retries + 1

    runtime_error_message = "Runtime error message"
    exception = RuntimeError(runtime_error_message)

    with pytest.raises(RuntimeError, match="Retry limit reached\. Message handler has failed .*"):
        runner.on_error(exception)

    runner._run.assert_not_called()

    logs = debug_logs.text
    check_strings = [
        "Error in message handler: {0}".format(exception),
    ]
    for string in check_strings:
        assert_that(logs, contains_string(string))
