ChangeLog
=========

0.7.2 (2021-8-23)
------------------

* Don't raise 404 errors when deleting tags during rollback

0.7.1 (2021-8-20)
------------------

* Fix installation of 'docker' dependency on Python 2.6

0.7.0 (2021-8-18)
------------------

* Add hooks to declare events of interest
* Create documentation
* Add option to execute commands inside a container
* Add pagination support for getting all tags via Docker HTTP API
* Capture IIB operation exception
* Get index image manifests with its own token
* Lower python-qpid-proton version


0.6.0 (2021-7-14)
------------------

* Create entrypoint for removing a Quay repo
* Create entrypoint for clearing a Quay repo
* Add signature removal to tag-docker operations
* Drop unnecessary 'external_repos'
* Add using extra Quay tokens for OSBS organizations
* Allow specifying multiple repos in remove-repo and clear-repo tasks
* Skip signing when no operator claim messages are constructed
* Add support for delimeter-less repositories
* Change "repo" parameter of claim messages to have external representation
* Fix loggers per pubtools conventions
* Check username in output of skopeo --get-login
* Remove the usage of Quay API reading repo data
* Add signature removal for IIB operations
* Update sigstore to be up-to-date with current implementation
* Allow pushing to non-existent repo

0.5.0 (2021-6-2)
------------------

* Fix intermediate index image
* Implement tag docker
* Add skip to signing if signing key is None
* Fix pub XMLRPC call
* Implement entrypoints for IIB methods

0.4.0 (2021-5-4)
------------------

* Implement push-docker prototype
* Change signing order to happen before pushing
* Use intermediate index image for signing

0.3.0 (2021-2-11)
------------------

* Fix the versioning constraint of pyrsistent dependency

0.2.0 (2021-2-9)
------------------

* Fix the definition of requirements.txt, allowing installation on Python 2.6

0.1.0 (2021-2-9)
------------------

* Initial release.
* Added tag image entrypoint
* Added merge manifest list entrypoint
* Added push docker code skeleton
