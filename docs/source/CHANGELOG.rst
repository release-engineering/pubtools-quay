ChangeLog
=========

0.10.1 (2022-6-17)
--------------------
* Remove duplicate destinations when pushing docker
* Listen on specific sub topic on signing service

0.10.0 (2022-6-01)
--------------------
* Fix arch of amd64 image
* Return empty manifest claims when there's nothing to sign
* Remove sorting of Push items
* Unpin the version of python-qpid-proton
* Remove created from claim message
* Change condition to not require hashing
* Push multiarch image when the current destination doesn't have a ML
* Poll for consistent results of whether a tag exists

0.9.3 (2022-04-01)
--------------------
* Fixing signing issues
* Skip getting v2s1 digest for non-amd64 images
* Less skopeo login to source registry
* Tolerate get_manifest 404 in image untagger

0.9.2 (2022-03-02)
--------------------
* Add a timeout to all HTTP requests
* Removed the option for entrypoints to send UMB messages

0.9.1 (2022-02-02)
------------------

* Fixed creating manifests for v2ch2 single arch containers

0.9.0 (2022-28-1)
------------------

* Support v2ch2 single arch containers
* Support v2ch1 containers
* Run rollback only when all index image builds fail
* Add retries to image tagging as a part of pushes
* Skip checking for repo deprecation based on value in target settings
* Support extra source host for quay operations
* Sign V2S1 manifests
* Tag index image timestamps with permanent index image as a source


0.8.3 (2021-10-6)
------------------

* Fix the usage of overwrite from index

0.8.2 (2021-10-6)
------------------

* Make deprecation list functionality optional

0.8.1 (2021-10-5)
------------------

* Disable sending UMB messages for taggign and untagging images

0.8.0 (2021-9-7)
------------------

* Use SSL certificates for Pyxis authentication
* Remove duplicate digests when getting signatures from Pyxis
* Remove return of push_docker entrypoint

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
