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
* pubtools-quay-merge-manifest-list - Merge manifest lists of new and old images. The architectures
  of new (source) image overwrite destination's archs. Archs missing from the source image will
  still remain in the merged manifest list. Destination image's manifest list is overwritten by
  the merged manifest list. 
* pubtools-quay-untag - Remove tags from quay repositories. Tags to remove are specified by
  image references. In addition to Docker credentials, Quay API OAuth token has to be specified. 
  Script will not perform the untagging operation if some image in a repo will lose its last
  tag. In this scenario, untagging can be forced by using the --remove-last argument.

Setup
=====

::

  $ pip install -r requirements.txt
  $ pip install . 
  or
  $ python setup.py install

Usage
=====

Locally copy an image from source to destination. Quay password is injected
from the environment variable.
::

  $ export QUAY_PASSWORD=token
  $ pubtools-quay-tag-image \
    --source-ref quay.io/source/image:34 \
    --dest-ref quay.io/target/image:34 \
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

Connect to a remote host via ssh (using private key), perform the copying, and send a UMB message.
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
    --send-umb-msg \
    --umb-url amqps://url:5671 \
    --umb-url amqps://url2:5671 \
    --umb-cert /path/to/file.crt \
    --umb-topic VirtualTopic.eng.pub.some_topic

Merge manifest lists of source-ref and dest-ref and overwrite dest-ref with the result.
::

  $ export QUAY_PASSWORD=token
  $ pubtools-quay-merge-manifest-list \
    --source-ref quay.io/src/image:1 \
    --dest-ref quay.io/dest/image:1 \
    --quay-user quay+username

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
    --quay-user quay+username \

