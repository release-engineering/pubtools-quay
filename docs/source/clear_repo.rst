Clear repo
==========

.. py:module:: pubtools._quay.clear_repo

Entrypoint used for clearing Quay repositories. All images will be removed from the specified repo, while the repo will not be deleted. Signatures of the deleted images will be removed.

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