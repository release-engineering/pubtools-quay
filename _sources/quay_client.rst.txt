Quay Client
===========

Class used for performing Docker HTTP API queries on Quay. Only necessary queries have been implemented, though more may be added, as required. Standard authentication procedure is also handled by this class.

Authentication details can be found at https://docs.docker.com/registry/spec/auth/token/

Full Docker HTTP API reference can be found at https://docs.docker.com/registry/spec/api/

.. py:module:: pubtools._quay.quay_client

.. autoclass:: QuayClient

   .. automethod:: __init__
   .. automethod:: get_manifest
   .. automethod:: get_manifest_digest
   .. automethod:: upload_manifest
   .. automethod:: get_repository_tags
   .. automethod:: _request_quay
   .. automethod:: _authenticate_quay
   .. automethod:: _parse_and_validate_image_url
