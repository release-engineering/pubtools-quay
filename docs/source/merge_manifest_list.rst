Merge manifest lists
====================

.. py:module:: pubtools._quay.merge_manifest_list

Entrypoint used for merging manifest lists of two images in Quay. ManifestListMerger class is invoked and used.

CLI reference
-------------

.. argparse::
   :module: pubtools._quay.merge_manifest_list
   :func: setup_args
   :prog: pubtools-quay-merge-manifest-list

Examples
-------------

Merge manifest lists of source-ref and dest-ref and overwrite dest-ref with the result.
::

  $ export QUAY_PASSWORD=token
  $ pubtools-quay-merge-manifest-list \
    --source-ref quay.io/src/image:1 \
    --dest-ref quay.io/dest/image:1 \
    --quay-user quay+username