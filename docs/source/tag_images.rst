Tag images
==========

.. py:module:: pubtools._quay.tag_images

Entrypoint used for copying an image to a destination/multiple destinations. If specified, copying operation may be performed on a remote machine via SSH.


CLI reference
-------------

.. argparse::
   :module: pubtools._quay.tag_images
   :func: setup_args
   :prog: pubtools-quay-tag-image

API reference
-------------

.. autofunction:: tag_images

Examples
-------------

Locally copy an image from source to destination. Quay password is injected
from the environment variable.
::

  $ export QUAY_PASSWORD=token
  $ pubtools-quay-tag-image \
    --source-ref quay.io/source/image:34 \
    --dest-ref quay.io/target/image:34 \
    --quay-user quay+username \

Locally copy an image from source to destination. Use extra login and password for source ref
::

  $ export QUAY_PASSWORD=token
  $ export SOURCE_QUAY_PASSWORD=token2
  $ pubtools-quay-tag-image \
    --source-ref quay.io/source/image:34 \
    --dest-ref quay.io/target/image:34 \
    --source-quay-user source-quay+username \
    --quay-user quay+username \

Connect to a remote host via ssh (using password) and perform the copying to multiple destinations.
::

  $ export QUAY_PASSWORD=token
  $ export SSH_PASSWORD=123456
  $ pubtools-quay-tag-image \
    --source-ref quay.io/source/image:34 \
    --dest-ref quay.io/target/image:34 \
    --dest-ref quay.io/target/image2:34 \
    --quay-user quay+username \
    --remote-exec \
    --ssh-remote-host 127.0.0.1 \
    --ssh-remote-host-port 2222 \
    --ssh-username user

Connect to a remote host via ssh (using private key), perform the copying
::

  $ export QUAY_PASSWORD=token
  $ export SSH_PASSWORD=123456
  $ pubtools-quay-tag-image \
    --source-ref quay.io/source/image:34 \
    --dest-ref quay.io/target/image:34 \
    --quay-user quay+username \
    --remote-exec \
    --ssh-remote-host 127.0.0.1 \
    --ssh-remote-host-port 2222 \
    --ssh-username user \
    --ssh-key-filename /path/to/file.key \

Copy to multiple destination inside a specified container.
::

  $ export QUAY_PASSWORD=token
  $ export SSH_PASSWORD=123456
  $ pubtools-quay-tag-image \
    --source-ref quay.io/source/image:34 \
    --dest-ref quay.io/target/image:34 \
    --dest-ref quay.io/target/image2:34 \
    --quay-user quay+username \
    --container-exec \
    --container-image quay.io/namespace/image:1 \
    --docker-url https://some-url.com \
    --docker-timeout 120 \
    --docker-verify-tls \
    --docker-cert-path /some/path
