Quay Session
============

This is a helper class used by Quay API Client and Quay Client and used primarily for holding a session and not requiring authentication for each query.

.. py:module:: pubtools._quay.quay_session

.. autoclass:: QuaySession

   .. automethod:: __init__
   .. automethod:: get
   .. automethod:: post
   .. automethod:: put
   .. automethod:: delete
   .. automethod:: request
   .. automethod:: _api_url
   .. automethod:: set_auth_token
