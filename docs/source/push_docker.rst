Push Docker
===========

This is the main class for the Push Docker workflow, which is the primary workflow for container and operator related content. 

.. py:module:: pubtools._quay.push_docker

.. autoclass:: PushDocker

   .. automethod:: run
   .. automethod:: __init__
   .. automethod:: verify_target_settings
   .. automethod:: get_docker_push_items
   .. automethod:: get_operator_push_items
   .. automethod:: get_repo_metadata
   .. automethod:: check_repos_validity
   .. automethod:: generate_backup_mapping
   .. automethod:: rollback
   .. automethod:: remove_old_signatures
