Untag images
============

.. py:module:: pubtools._quay.untag_images

Entrypoint used for removing tags (images) from Quay. The script will refuse to perform the removal if a last reference of an image is to be removed. This may be overruled by specifying the --remove-last flag. Optionally, an UMB message may be send notifying of the removed image tags.

CLI reference
-------------

.. argparse::
   :module: pubtools._quay.untag_images
   :func: setup_args
   :prog: pubtools-quay-untag

API reference
-------------

.. autofunction:: untag_images

Examples
-------------

Untag multiple images and send a UMB message.
::

  $ export QUAY_PASSWORD=token
  $ export QUAY_API_TOKEN=oauth_token
  $ pubtools-quay-tag-image \
    --reference quay.io/src/image:1 \
    --reference quay.io/src/image:2 \
    --quay-user quay+username \
    --remote-exec \
    --ssh-remote-host 127.0.0.1 \
    --ssh-remote-host-port 2222 \
    --ssh-username user \
    --ssh-key-filename /path/to/file.key \
    --send-umb-msg \
    --umb-url amqps://url:5671 \
    --umb-url amqps://url2:5671 \
    --umb-cert /path/to/file.crt \
    --umb-topic VirtualTopic.eng.pub.some_topic

Untag an image and force the operation in case the tag is a last reference of some digest.
::

  $ export QUAY_PASSWORD=token
  $ export QUAY_API_TOKEN=oauth_token
  $ pubtools-quay-tag-image \
    --reference quay.io/src/image:1 \
    --remove-last \
    --quay-user quay+username