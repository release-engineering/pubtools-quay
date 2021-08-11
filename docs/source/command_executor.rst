Command Executor
================

.. py:module:: pubtools._quay.command_executor

Classes used for executing shell commands. Main class Executor contains a concrete implementation of various shell commands that are used throughout pubtools-quay. The logic of a command execution is not implemented in this class. The children classes (LocalExecutor, RemoteExecutor) contain the logic for generic command execution based on the environment type (remote or local). New classes may be implemented if a new execution style is required.

Base class
----------

.. autoclass:: Executor

   .. automethod:: __enter__
   .. automethod:: __exit__
   .. automethod:: skopeo_login
   .. automethod:: tag_images
   .. automethod:: skopeo_inspect

Children classes
----------------

.. autoclass:: LocalExecutor

   .. automethod:: __init__
   .. automethod:: _run_cmd

.. autoclass:: RemoteExecutor

   .. automethod:: __init__
   .. automethod:: _run_cmd

.. autoclass:: ContainerExecutor

   .. automethod:: __init__
   .. automethod:: __exit__
   .. automethod:: _run_cmd
   .. automethod:: _add_file
   .. automethod:: skopeo_login