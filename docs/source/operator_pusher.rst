Operator Pusher
===============

This class handles all the operator-related parts of the full Push Docker workflow. 

.. py:module:: pubtools._quay.operator_pusher

.. autoclass:: OperatorPusher

   .. automethod:: build_index_images
   .. automethod:: push_index_images
   .. automethod:: __init__
   .. automethod:: _get_immutable_tag
   .. automethod:: public_bundle_ref
   .. automethod:: pyxis_get_ocp_versions
   .. automethod:: version_items_mapping
   .. automethod:: get_deprecation_list
   .. automethod:: pubtools_iib_get_common_args
   .. automethod:: iib_add_bundles
   .. automethod:: iib_remove_operators
   .. automethod:: get_existing_index_images
