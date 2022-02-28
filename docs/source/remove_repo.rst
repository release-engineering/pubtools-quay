Remove repo
===========

.. py:module:: pubtools._quay.remove_repo

Entrypoint used for removing Quay repositories. All the images along with the repository itself will be removed. Signatures of the deleted images will be removed.

CLI reference
-------------

.. argparse::
   :module: pubtools._quay.remove_repo
   :func: setup_args
   :prog: pubtools-quay-remove-repo

API reference
-------------

.. autofunction:: remove_repositories

Examples
-------------

Clear multiple repos
::

  $ export QUAY_PASSWORD=token
  $ export QUAY_API_TOKEN=oauth_token
  $ pubtools-quay-clear-repo \
    --repositories namespace/repo1,namespace/repo2 \
    --quay-org quay-organization
    --quay-user quay+username \
    --pyxis-server https://pyxis-server.com/ \
    --pyxis-krb-principal pyxis-principal \
