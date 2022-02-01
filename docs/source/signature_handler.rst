Signature Handler
=================

Classes which handle container image signing. Base class, "SignatureHandler" contains common operations for all signing workflows. Children classes contain specific implementations for given workflows.

.. py:module:: pubtools._quay.signature_handler

.. autoclass:: SignatureHandler

   .. automethod:: __init__
   .. automethod:: src_quay_client
   .. automethod:: create_manifest_claim_message
   .. automethod:: get_tagged_image_digests
   .. automethod:: get_signatures_from_pyxis
   .. automethod:: remove_duplicate_claim_messages
   .. automethod:: filter_claim_messages
   .. automethod:: get_signatures_from_radas
   .. automethod:: upload_signatures_to_pyxis
   .. automethod:: validate_radas_messages

.. autoclass:: ContainerSignatureHandler

   .. automethod:: construct_item_claim_messages
   .. automethod:: construct_variant_claim_messages
   .. automethod:: sign_container_images

.. autoclass:: OperatorSignatureHandler

   .. automethod:: construct_index_image_claim_messages
   .. automethod:: sign_operator_images
   .. automethod:: sign_task_index_image

.. autoclass:: BasicSignatureHandler

   .. automethod:: __init__
   .. automethod:: sign_claim_messages
