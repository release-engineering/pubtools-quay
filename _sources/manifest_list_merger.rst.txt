Manifest list merger
====================

This class handles the merging of manifest lists, as well as other use-cases which require manifest list modifications.

.. py:module:: pubtools._quay.manifest_list_merger

.. autoclass:: ManifestListMerger

   .. automethod:: merge_manifest_lists
   .. automethod:: __init__
   .. automethod:: set_quay_clients
   .. automethod:: get_missing_architectures
   .. automethod:: _add_missing_architectures
   .. automethod:: merge_manifest_lists_selected_architectures
