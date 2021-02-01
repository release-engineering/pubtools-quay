===============
 pubtools-quay
===============

Set of scripts used for operating with Quay service


Requirements
============

* Python 2.6+
* Python 3.5+
* Skopeo is required for the tagging operation

Features
========
* pubtools-quay-tag-image - Copy a quay image from source to destination(s)

Setup
=====

::

  $ pip install -r requirements.txt
  $ pip install . 
  or
  $ python setup.py install

Usage
=====

Locally copy an image from source to destination. Quay token is injected
from the environment variable.
::
  $ export AUTH_TOKEN=token
  $ pubtools-quay-tag-image \
    --source-ref quay.io/source/image:34 \
    --dest-ref quay.io/target/image:34 \
    --quay-user quay+username \

Connect to a remote host via ssh (using password) and perform the copying to multiple destinations.
::
  $ export AUTH_TOKEN=token
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

Connect to a remote host via ssh (using private key), perform the copying, and send a UMB message.
::
  $ export AUTH_TOKEN=token
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
    --send-umb-msg \
    --umb-url amqps://url:5671 \
    --umb-url amqps://url2:5671 \
    --umb-cert /path/to/file.crt \
    --umb-topic VirtualTopic.eng.pub.some_topic