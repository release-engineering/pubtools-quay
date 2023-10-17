Security manifest pusher
========================

.. py:module:: pubtools._quay.security_manifest_pusher

Class used for creating and pushing container security manifests in the form of attestations. THe manifests are extracted from a pushed image, and the product name is added as a metadata. If there is an already existing security manifest, multiple product names can be merged.

.. autoclass:: SecurityManifestPusher

   .. automethod:: __init__
   .. automethod:: cosign_get_security_manifest
   .. automethod:: cosign_get_existing_attestation
   .. automethod:: cosign_attest_security_manifest
   .. automethod:: cosign_triangulate_image
   .. automethod:: get_security_manifest_from_attestation
   .. automethod:: security_manifest_get_products
   .. automethod:: get_destination_repos
   .. automethod:: delete_existing_attestation
   .. automethod:: security_manifest_add_products
   .. automethod:: get_source_item_security_manifests
   .. automethod:: get_multiarch_item_security_manifests
   .. automethod:: push_item_security_manifests
   .. automethod:: push_security_manifests
