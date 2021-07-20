Signature Remover
=================

Class used for removing unnecessary signatures. Multiple ways to delete signatures exist, based on a particular use-case.

.. py:module:: pubtools._quay.signature_remover

.. autoclass:: SignatureRemover

   .. automethod:: __init__
   .. automethod:: quay_client
   .. automethod:: set_quay_client
   .. automethod:: get_signatures_from_pyxis
   .. automethod:: remove_signatures_from_pyxis
   .. automethod:: get_repository_digests
   .. automethod:: remove_repository_signatures
   .. automethod:: remove_tag_signatures
   .. automethod:: get_index_image_signatures
