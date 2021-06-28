# this code has been copied from rcm-pub (pubd/lib/docker_signature.py)
import logging
import os
import json
import proton.handlers
import proton.reactor
import proton

import monotonic

LOG = logging.getLogger("pubtools.quay")

# There are some linting errors since this was copied from rcm-pub
# flake8: noqa: D101, D107, D102, D205, D400, D403


class MessageHandlerTimeoutException(Exception):

    pass


class ManifestClaimsHandler(proton.handlers.MessagingHandler):
    """
    Class for handling communication with RADAS via UMB.

    The manifest claims handler waits for messages from the UMB
    and will check against the manifest claims sent until all claims are received.

    - umb_urls - list of Universal Message Bus url/location
        will look like ["amqps://umb.fake.redhat.com", ...]
    - radas_address - the address/topic to listen to for RADAS messages
        e.g "topic://VirtualTopic.eng.robosignatory.container.sign"
    - claim_messages - the messages sent which will be used
        to match up responses (as you can get responses from other workers).
        This will use the request_id field
    - pub_cert - the certificate + private key combination from issued
        to connect to the Universal Message bus.
    - ca_cert - the certificate authority for the the pub_cert that
        is used to identify pub (and others) connecting to the UMB
    - timeout - the time in seconds which the message handler will
        attempt to retrieve messages. Will fail with a
        MessageHandlerTimeoutException if this is exceeded
    - message_sender_callback - this is the message_sender_callback
        that will be called with no parameters to send the messages
        to RADAS for signing. This is called after the receiver is connected
        to avoid any potential race conditions due to slow network
    """

    TIMER_TASK_DELAY = int(os.getenv("PUB_UMB_TIMER_TASK_DELAY", "10"))
    # delay between polls

    def __init__(
        self,
        umb_urls,
        radas_address,
        claim_messages,
        pub_cert,
        ca_cert,
        timeout,
        throttle,
        retry,
        message_sender_callback,
    ):
        super(ManifestClaimsHandler, self).__init__()
        self.umb_urls = umb_urls
        self.radas_address = radas_address
        self.claim_messages = list(claim_messages)
        self.received_messages = []
        self.timeout = timeout
        self.throttle = throttle
        self.retry = retry
        self.timer_task = None
        self.receiver = None
        self.message_sender_callback = message_sender_callback
        self.awaiting_response = {}  # {request_id: monotonic.monotonic()}
        self.retry_count = {}  # {request_id: 1/2}
        # a mutable list caches messages to send
        self.to_send = list(claim_messages)
        # {request_id: message} a map used to find wanted message by request_id
        self.id_msg_map = {}
        for msg in self.claim_messages:
            self.id_msg_map[msg["request_id"]] = msg
        self.connected = False

        self.ssl_domain = proton.SSLDomain(proton.SSLDomain.MODE_CLIENT)
        self.ssl_domain.set_credentials(pub_cert, pub_cert, None)
        self.ssl_domain.set_trusted_ca_db(ca_cert)
        self.ssl_domain.set_peer_authentication(proton.SSLDomain.ANONYMOUS_PEER)

    def on_start(self, event):
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
        for request_id, started in sorted(list(self.awaiting_response.items())):
            if monotonic.monotonic() - started > self.timeout:
                if request_id not in self.retry_count or self.retry_count[request_id] < self.retry:
                    self.retry_count.setdefault(request_id, 0)
                    self.retry_count[request_id] += 1
                    LOG.warn(
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
                    LOG.warn("Stopping message event loop due to timeout %s", request_id)
                    event.container.stop()
                    raise MessageHandlerTimeoutException()

        # send more requests if number of waiting < throttle
        spots = self.throttle - len(self.awaiting_response)
        if self.to_send and spots > 0:
            # if there's free spots, send messages in queue
            self._send_message(min(len(self.to_send), spots))

        # schdule the next timer task
        self.timer_task = event.container.schedule(self.TIMER_TASK_DELAY, self)

    def on_link_opened(self, event):
        # do the message sending to when the connection has been opened
        # as there is the potential for messages to be dropped.
        if event.receiver == self.receiver:
            # link's open, cancel the scheduled timer task, which was for connecting
            # timing out.
            self.timer_task.cancel()
            self.connected = True
            self._send_message()
            self.timer_task = event.container.schedule(self.TIMER_TASK_DELAY, self)
        else:
            LOG.warn("Unexpected on_link_opened event")

    def on_message(self, event):
        """Once receive a message, check if it's expected by checking the awaiting_response,
        if it is, then append it to received and remove it from awaiting_response.
        """
        outer_message = json.loads(event.message.body)
        radas_message = outer_message["msg"]
        request_id = radas_message["request_id"]

        if request_id in self.awaiting_response:
            LOG.info("Received signing response: %s", request_id)
            self.awaiting_response.pop(request_id)
            self.received_messages.append(radas_message)
            if not self.to_send and not self.awaiting_response:
                LOG.info("All requests satisfied, closing connection...")
                self.receiver.close()
                event.connection.close()
                self.timer_task.cancel()
                LOG.info("Connection closed.")
        else:
            LOG.debug("Ignored signing response: %s", radas_message["request_id"])

    def on_connection_closed(self, event):
        LOG.debug("Messaging event: connection_closed")

    def on_session_closed(self, event):
        LOG.debug("Messaging event: session_closed")

    def on_link_closed(self, event):
        LOG.debug("Messaging event: link_closed")

    def on_connection_closing(self, event):
        LOG.debug("Messaging event: connection_closing")

    def on_session_closing(self, event):
        LOG.debug("Messaging event: session_closing")

    def on_link_closing(self, event):
        LOG.debug("Messaging event: link_closing")

    def on_disconnected(self, event):
        LOG.debug("Messaging event: disconnected")

    def _send_message(self, count=None):
        if count is None:
            count = min(len(self.to_send), self.throttle)
        messages = self.to_send[:count]
        LOG.info("Sending %s messages...", count)
        self.message_sender_callback(messages)
        # remove sent message from sending queue
        del self.to_send[:count]

        # add sent message's request id to waiting queue
        for msg in messages:
            self.awaiting_response[msg["request_id"]] = monotonic.monotonic()
