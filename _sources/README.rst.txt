===============
    Overview
===============

Set of scripts used for operating with the Quay service

Details
============

pubtools-quay is a library used for performing various container-related workflows and standalone operations. The library is utilized by Red Hat's internal tooling for pushing and managing the container images it serves to customers.

Some scripts support a CLI invocation and may be utilized by end-users directly. These are mostly content management operations and are expected to be performed ad-hoc and on a need-to basis. Other scripts can only be invoked programmatically from a different Python code. These are generally a part of standard content workflows, and are expected to be invoked by internal Red Hat tooling. 

The internal service which utilizes this library is called "rcm-pub" (hence pubtools in the name). Other internal services which the tooling requires are IIB, Pyxis, RADAS, and UMB. The container images are managed in Quay.io. It's unlikely that the workflows would function with a generic Docker registry.

Requirements
============

- Python 2.6+
- Python 3.5+
- Skopeo is required for the tagging operation
- Internal Python library 'rhmsg' is required for sending UMB messages

Setup
=====

::

  $ pip install -r requirements.txt
  $ pip install . 
  or
  $ python setup.py install

