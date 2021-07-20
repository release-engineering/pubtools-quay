Clear repo
==========

.. py:module:: pubtools._quay.clear_repo

Entrypoint used for clearing Quay repositories. All images will be removed from the specified repo, while the repo will not be deleted. Signatures of the deleted images will be removed. Optionally, a UMB message will be sent notifying of the cleared repositories.

CLI reference
-------------

.. argparse::
   :module: pubtools._quay.clear_repo
   :func: setup_args
   :prog: pubtools-quay-clear-repo

API reference
-------------

.. autofunction:: clear_repositories

Examples
-------------

Clear multiple repos and send a UMB message.
::

  $ export QUAY_PASSWORD=token
  $ export QUAY_API_TOKEN=oauth_token
  $ pubtools-quay-clear-repo \
    --repositories namespace/repo1,namespace/repo2 \
    --quay-org quay-organization
    --quay-user quay+username \
    --pyxis-server https://pyxis-server.com/ \
    --pyxis-krb-principal pyxis-principal \
    --send-umb-msg \
    --umb-url amqps://url:5671 \
    --umb-url amqps://url2:5671 \
    --umb-cert /path/to/file.crt \
    --umb-topic VirtualTopic.eng.pub.some_topic