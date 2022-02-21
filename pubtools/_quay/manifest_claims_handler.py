# this code has been copied from rcm-pub (pubd/lib/docker_signature.py)
import logging
import os
import json

import monotonic
import proton
from proton.handlers import MessagingHandler
from proton.reactor import Container

LOG = logging.getLogger("pubtools.quay")

# There are some linting errors since this was copied from rcm-pub
# flake8: noqa: D101, D107, D102, D205, D400, D403


class MessageHandlerTimeoutException(Exception):

    pass


class AMQPError(Exception):
    """Base class for AMQP-specific errors."""

    pass


class AMQPEndpointError(AMQPError):
    """Signal an error with one of the AMQP endpoints.

    Parameters:
        endpoint_name (:py:obj:`str`): The endpoint at which the error
            occurred. Expected value is one of 'Connection', 'Session',
            'Link' or 'Transport'. The value provided will be title-cased,
            by the constructor so any "ALL UPPER" or "all lower" strings
            will be converted to "All Upper" or "All Lower".
        error_label (:py:obj:`str`): The name or label of the error that
            occurred e.g. `amqp:resource-limit-exceeded`. This class does
            not verify that the provided name matches expected error types
            from the AMQP specification. If no name is provided a default of
            'Unknown' is used.
        description (:py:obj:`str`): The description of the error that occurred.
            If no description is provided a default of 'No error description provided.'
            is used.
    """

    def __init__(
        self,
        endpoint_name,
        error_label="Unknown",
        description="No error description provided.",
    ):
        msg = "({endpoint!s}) {name}: {description}".format(
            endpoint=endpoint_name, name=error_label, description=description
        )
        super(AMQPEndpointError, self).__init__(msg)

    def __str__(self):
        # The message without the context of AMQPEndpointError doesn't mean much.
        return repr(self)


def _get_endpoint_error_condition(endpoint):
    """Return the error condition on this endpoint if there is one.

    If there's no local error condition, return the remote error
    condition if there is one.

    Parameters:
        :obj:`proton.Endpoint`: The Proton Endpoint from which the error
            condition is being retrieved.

    Returns:
        :obj:`Optional[proton.Condition]`: The local endpoint error condition
            if there is one, or the remote endpoint error condition if there
            is one.
    """
    return endpoint.condition or endpoint.remote_condition


def do_nothing(*_, **__):
    """A convenient placeholder function that does, as advertised, nothing."""
    pass  # pragma: no cover


def raise_error(error):
    """A convenient placeholder function that raises an error."""
    raise error  # pragma: no cover


class ManifestClaimsHandler(MessagingHandler):
    """
    The manifest claims handler waits for messages from the UMB
    and will check against the manifest claims sent until all claims are received.

    Parameters:
        settings (:obj:`UMBSettings`): A UMBSettings object prescribing the
            correct settings for the remote UMB peer through which communication
            with Radas happens.
        claim_messages (:obj:`Sequence[Mapping[str, Any]]`): The manifest claim
            messages that need to be signed by Radas.
        message_sender_callback (:obj:`Callable[[Sequence[Mapping[str, Any]]], None]:
            A callback that will be invoked with to send messages to Radas for
            signing.
        on_message_callback (:obj:`Callable[[Mapping[str, Any]], None]:
            Callback invoked if an incoming response is matched with
            with a request. The callback can expect to be invoked with the
            deserialized response message.
        on_error_callback (:obj:`Callable[[Exception], None]`):
            Callback invoked when an unhandled error occurs at the protocol
            level.
    """

    TIMER_TASK_DELAY = int(os.getenv("PUB_UMB_TIMER_TASK_DELAY", "10"))
    """int: The default delay after which scheduled timer tasks should run."""

    _PROTON_KNOWN_UNHANDLED_ERRORS = frozenset(
        ("amqp:resource-limit-exceeded#local-idle-timeout expired",)
    )
    """frozenset: A set of {error.name}#{error.description} tags.

    There are errors that Proton handles itself using built-in Handler
    implementations e.g. start attempting to reconnect when a connection
    error occurs.

    These are errors that Proton has demonstrated it does not handle
    e.g. local-idle-timeout from RHELDST-8317.
    """

    def __init__(
        self,
        settings,
        claim_messages,
        message_sender_callback,
        on_message_callback=do_nothing,
        on_error_callback=raise_error,
    ):
        super(ManifestClaimsHandler, self).__init__()
        self.umb_urls = settings.broker_urls
        self.radas_address = settings.radas_address
        self.claim_messages = list(claim_messages)
        self.timeout = settings.signing_timeout
        self.throttle = settings.signing_throttle
        self.retry = settings.signing_retry
        self.timer_task = None
        self.receiver = None
        self.message_sender_callback = message_sender_callback
        self._on_next = on_message_callback
        self._on_error = on_error_callback
        self.awaiting_response = {}  # {request_id: monotonic.monotonic()}
        self.retry_count = {}  # {request_id: 1/2}
        # a mutable list caches messages to send
        self.to_send = list(claim_messages)
        # {request_id: message} a map used to find wanted message by request_id
        self.id_msg_map = {}
        for msg in self.claim_messages:
            self.id_msg_map[msg["request_id"]] = msg  # pragma: no cover
        self.connected = False

        self.ssl_domain = proton.SSLDomain(proton.SSLDomain.MODE_CLIENT)
        self.ssl_domain.set_credentials(settings.pub_cert, settings.pub_cert, None)
        self.ssl_domain.set_trusted_ca_db(settings.ca_cert)
        self.ssl_domain.set_peer_authentication(proton.SSLDomain.ANONYMOUS_PEER)

    def on_start(self, event):  # pragma: no cover
        LOG.debug("Message event loop starting, connecting to brokers...")
        conn = event.container.connect(
            urls=self.umb_urls, ssl_domain=self.ssl_domain, sasl_enabled=False
        )
        self.receiver = event.container.create_receiver(conn, self.radas_address)
        self.timer_task = event.container.schedule(self.timeout, self)
        # schedule a timer task, if the connection to UMB could be established, raise exception.
        LOG.debug("Message event loop started")

    def on_timer_task(self, event):
        """timer task has three functionalities:
        1. if it couldn't be connected to brokers, then after self.timeout, exception
           will be raised.
        2. Check if any request is timed out, if it is, then continue checking the retry history
            - if the retry history shows it's been tried more than 3 times, then stop loop.
            - if not, then remove it from awaiting_response dict and send it back to to_send
              queue, bump the retry count.
        3. Check if the number of requests in processing has reached throttle or not, if not
           then send corresponding number of messages.
        """
        if not self.connected:
            LOG.error("Couldn't connect to brokers after %s seconds", self.timeout)
            event.container.stop()
            raise MessageHandlerTimeoutException()
        for request_id, started in list(self.awaiting_response.items()):
            if monotonic.monotonic() - started > self.timeout:
                if request_id not in self.retry_count or self.retry_count[request_id] < self.retry:
                    self.retry_count.setdefault(request_id, 0)
                    self.retry_count[request_id] += 1
                    LOG.warning(
                        "Didn't receive response in %s for request %s, will retry [%s/%s]",
                        self.timeout,
                        request_id,
                        self.retry_count[request_id],
                        self.retry,
                    )
                    # append to resend queue and remove from awaiting_response queue
                    self.to_send.append(self.id_msg_map[request_id])
                    self.awaiting_response.pop(request_id)
                else:
                    LOG.warning("Stopping message event loop due to timeout %s", request_id)
                    event.container.stop()
                    raise MessageHandlerTimeoutException()

        # send more requests if number of waiting < throttle
        spots = max(0, self.throttle - len(self.awaiting_response))
        if spots:
            # if there's free spots, send messages in queue
            self._send_message(min(len(self.to_send), spots))

        # schedule the next timer task
        self.timer_task = event.container.schedule(self.TIMER_TASK_DELAY, self)

    def on_link_opened(self, event):
        # do the message sending to when the connection has been opened
        # as there is the potential for messages to be dropped.
        if event.receiver == self.receiver:  # pragma: no cover
            # link's open, cancel the scheduled timer task, which was for connecting
            # timing out.
            self.timer_task.cancel()
            self.connected = True
            self._send_message()
            self.timer_task = event.container.schedule(self.TIMER_TASK_DELAY, self)
        else:
            LOG.warning("Unexpected on_link_opened event")

    def on_message(self, event):
        """Once receive a message, check if it's expected by checking the awaiting_response,
        if it is, then append it to received and remove it from awaiting_response.
        """
        outer_message = json.loads(event.message.body)
        radas_message = outer_message["msg"]
        request_id = radas_message["request_id"]

        if request_id in self.awaiting_response:  # pragma: no cover
            LOG.info("Received signing response: %s", request_id)
            self.awaiting_response.pop(request_id)
            self._on_next(radas_message)
            if not self.to_send and not self.awaiting_response:
                LOG.info("All requests satisfied, closing connection...")
                self.receiver.close()
                event.connection.close()
                self.timer_task.cancel()
                LOG.info("Connection closed.")
        else:
            LOG.debug("Ignored signing response: %s", radas_message["request_id"])

    def on_connection_closing(self, event):
        LOG.debug("Messaging event: connection_closing")

    def on_connection_closed(self, event):
        LOG.debug("Messaging event: connection_closed")

    def on_connection_error(self, event):
        LOG.debug("Messaging event: connection_error")
        self._endpoint_error(event, event.connection)

    def on_session_closing(self, event):
        LOG.debug("Messaging event: session_closing")

    def on_session_closed(self, event):
        LOG.debug("Messaging event: session_closed")

    def on_session_error(self, event):
        LOG.debug("Messaging event: session_error")
        self._endpoint_error(event, event.session)

    def on_link_closing(self, event):
        LOG.debug("Messaging event: link_closing")

    def on_link_closed(self, event):
        LOG.debug("Messaging event: link_closed")

    def on_link_error(self, event):
        LOG.debug("Messaging event: link_error")
        self._endpoint_error(event, event.link)

    def on_transport_error(self, event):
        LOG.debug("Messaging event: transport_error")
        # transport errors appear to be handled by Proton
        # in most cases, so check for a known case where
        # that isn't true, and consider that an actual error
        self._endpoint_error_if_unhandled(event, event.transport)

    def on_disconnected(self, event):
        LOG.debug("Messaging event: disconnected")

    def _endpoint_error(self, event, endpoint):
        condition = _get_endpoint_error_condition(endpoint)
        if condition is None:
            error = AMQPEndpointError(endpoint_name=endpoint.__class__.__name__)
        else:
            error = AMQPEndpointError(
                endpoint_name=endpoint.__class__.__name__,
                error_label=condition.name,
                description=condition.description,
            )
        LOG.error(str(error))
        event.container.stop()
        self._on_error(error)

    def _endpoint_error_if_unhandled(self, event, endpoint):
        condition = _get_endpoint_error_condition(endpoint)
        if condition is not None:
            error_tag = "{condition.name}#{condition.description}".format(condition=condition)
            if error_tag in self._PROTON_KNOWN_UNHANDLED_ERRORS:
                self._endpoint_error(event, endpoint)

    def _send_message(self, count=None):
        if not self.to_send:  # pragma: no cover
            return

        if count is None:  # pragma: no cover
            count = min(len(self.to_send), self.throttle)

        messages = self.to_send[:count]
        LOG.info("Sending %s messages...", count)
        self.message_sender_callback(messages)
        # remove sent message from sending queue
        del self.to_send[:count]

        # add sent message's request id to waiting queue
        for msg in messages:
            self.awaiting_response[msg["request_id"]] = monotonic.monotonic()


class _ManifestClaimsRunner(object):
    """Wrap the execution of ManifestClaimsHandler and manage a bit of its lifecycle.

    This class handles restarting messaging in the event of an error, and
    imposes a maximum retry limit on the number of times messaging will
    be restarted.

    Parameters:
        settings (:obj:`UMBSettings`): A UMBSettings object prescribing the
            correct settings for the remote UMB peer through which communication
            with Radas happens.
        claim_messages (:obj:`Sequence[Mapping[str, Any]]`): The manifest claim
            messages that need to be signed by Radas.
        send_action (:obj:`Callable[[Sequence[Mapping[str, Any]]], None]:
            A callback that will be invoked with to send messages to Radas for
            signing.

    See Also:
        `ManifestClaimsHandler`

    """

    def __init__(self, settings, claim_messages, send_action):
        self._settings = settings
        self._claim_messages = claim_messages
        self._send_action = send_action
        self._retry_attempts = 0
        self._maximum_retries = settings.signing_retry
        self._received_messages = {}

    @property
    def received_messages(self):  # pragma: no cover
        """:obj:`Sequence[Mapping[str, Any]]`: The set of received messages."""
        return list(self._received_messages.values())

    def on_next(self, message):  # pragma: no cover
        """Track incoming response messages."""
        request_id = message["request_id"]
        self._received_messages.setdefault(request_id, message)

    def on_error(self, error):
        """Determines if messaging can and needs to be restarted, and does so if necessary."""
        LOG.error("Error in message handler: %s", error)

        if self._retry_attempts > self._maximum_retries:
            LOG.warning("Retry limit reached. Messaging will not be restarted!")
            return

        missing = [
            msg for msg in self._claim_messages if msg["request_id"] not in self._received_messages
        ]

        if not missing:
            LOG.info("No claims missing responses. Restart not required.")
            return

        self._retry_attempts += 1
        LOG.info(
            "Restarting message handler for %d remaining claims (retry %d/%d).",
            len(missing),
            self._retry_attempts,
            self._maximum_retries,
        )
        self._run(missing)

    def start(self):  # pragma: no cover
        """Start manifest claim messaging for the first time."""
        self._run(self._claim_messages)

    def _run(self, claims):  # pragma: no cover
        """Run manifest claim messaging with the given set of claims."""
        handler = ManifestClaimsHandler(
            self._settings,
            claims,
            self._send_action,
            on_message_callback=self.on_next,
            on_error_callback=self.on_error,
        )
        Container(handler).run()


class UMBSettings(object):
    __slots__ = [
        "broker_urls",
        "radas_address",
        "pub_cert",
        "ca_cert",
        "signing_timeout",
        "signing_throttle",
        "signing_retry",
    ]

    def __init__(
        self,
        broker_urls,
        radas_address="VirtualTopic.eng.robosignatory.container.sign",
        pub_cert="/etc/pub/umb-pub-cert-key.pem",
        ca_cert="/etc/pki/tls/certs/ca-bundle.crt",
        signing_timeout=600,
        signing_throttle=100,
        signing_retry=3,
    ):
        self.broker_urls = broker_urls
        self.radas_address = radas_address
        self.pub_cert = pub_cert
        self.ca_cert = ca_cert
        self.signing_timeout = signing_timeout
        self.signing_throttle = signing_throttle
        self.signing_retry = signing_retry
