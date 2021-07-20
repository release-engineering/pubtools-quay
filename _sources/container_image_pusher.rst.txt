Container image pusher
======================

.. py:module:: pubtools._quay.container_image_pusher

Class used for copying images in Quay. It supports both source (single-arch) and multiarch images. Logic for determining whether manifest list merging is necessary, or simple copy suffices is also contained in this class. This class handles all the container-related parts of the Push Docker workflow.

.. autoclass:: ContainerImagePusher

   .. automethod:: __init__
   .. automethod:: run_tag_images
   .. automethod:: copy_source_push_item
   .. automethod:: run_merge_workflow
   .. automethod:: copy_multiarch_push_item
   .. automethod:: push_container_images
