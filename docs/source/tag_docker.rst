Tag Docker
=================

This is the main class for the Tag Docker workflow, which is used for adding and deleting tags and architectures.

.. py:module:: pubtools._quay.tag_docker

.. autoclass:: TagDocker

   .. automethod:: __init__
   .. automethod:: run
   .. automethod:: quay_client
   .. automethod:: verify_target_settings
   .. automethod:: verify_input_data
   .. automethod:: check_input_validity
   .. automethod:: get_image_details
   .. automethod:: is_arch_relevant
   .. automethod:: tag_remove_calculate_archs
   .. automethod:: tag_remove_calculate_archs_source_image
   .. automethod:: tag_remove_calculate_archs_multiarch_image
   .. automethod:: tag_add_calculate_archs
   .. automethod:: copy_tag_sign_images
   .. automethod:: merge_manifest_lists_sign_images
   .. automethod:: run_untag_images
   .. automethod:: untag_image
   .. automethod:: manifest_list_remove_archs
