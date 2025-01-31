ChangeLog
=========

0.32.0 (2025-03-07)
-------------------
* Bumped pubtools-sign dependency

0.31.0 (2025-01-14)
-------------------
* Check related image only for add-bundles

0.30.0 (2025-01-13)
-------------------
* Disable stage check when removing arches
* Add additional tag to merged manifest list

0.29.0 (2024-11-20)
-------------------
* Restore a tag only once

0.28.0 (2024-10-18)
-------------------
* Support tagging OCI images
* Fix manifest list digest in tag docker

0.27.0 (2024-09-03)
-------------------
* Create entrypoint iib-add-deprecations

0.26.2 (2024-07-19)
-------------------
* Use tag reference in cosign identity

0.26.1 (2024-07-19)
-------------------
* Bumped pubtools-sign dependency

0.26.0 (2024-07-18)
-------------------
* Support multiple identities and tag annotations for cosign signing

0.25.0 (2024-06-24)
-------------------
* Support pub_reference in SignEntry which translates to --sign-container-identity for cosign


0.24.0 (2024-06-05)
-------------------
* Ensure that unusual cosign errors are raised
* Set pubtools-iib build-timeout argument based on target settings value
* Fix an issue where ML attestations are double encoded
* Add a retry to the attest command
* Ensure that a 404 error when deleting a tag is tolerated

0.23.0 (2024-05-29)
-------------------
* Sort backup items by repo
* Support untagging OCI images
* Update log message to show the reference with bad manifest type

0.22.0 (2024-05-21)
-------------------
Raise an error when manifest claims retry limit is reached
Manifest is outdated if both old and new manifests have digests

0.21.0 (2024-05-17)
-------------------
Fixed pushing index images to wrong namespace
Fixed removing index image signatures when there are no non fbc operators


0.20.0 (2024-05-10)
-------------------

* Fix SBOM publishing for the ML merge workflow
* Remove incompleteness_reasons field from SBOMs before publishing them

0.19.0 (2024-03-18)
-------------------

* Support cosign signing for container images

0.18.0 (2024-03-18)
-------------------

* Generate SBOM attestations for manifest lists

0.17.0 (2024-02-27)
-------------------

* Should not call IIB if bundle is opted in fbc and targets OCP >=4.11


0.16.0 (2024-02-08)
-------------------

* Instrument tracing for container push
* Add option to disable sending transparency logs to rekor

0.15.0 (2023-12-07)
-------------------

* End task when IIB request fails
* Set AWS KMS credentials from target settings
* Fix a bug where 0 IIB builds cause a push to fail

0.14.0 (2023-10-17)
-------------------

* Add --check-related-images option while calling iib-add-bundles
* Remove --skip-pulp argument when calling pubtools-iib

0.13.0 (2023-09-27)
-------------------

* Implement workflow to push container security manifests
* Support prerelease floating tag
* Remove images created by cosign

0.12.1 (2023-09-13)
-------------------

Allow radas messaging address to be formatable

0.12.0 (2023-07-25)
-------------------

* Support pre-release containers
* Better error reporting for skopeo copy commands
* Local executor for tag-docker operatoin

0.11.3 (2023-07-25)
-------------------

* Trigger building index images in parallel
* Make request session object per thread

0.11.2 (2023-07-10)
-------------------

* Add logs for adding and removing signatures
* Remove less signatures
* Use hotfix tag to sign an hotfix index image

0.11.1 (2023-05-15)
-------------------

* Make executor configurable
* Pin bandit version
* Add removing outdated signatures into task_status.jsonl

0.11.0 (2023-03-14)
-------------------

* Fix race condition in parallel container pushes
* Delete signatures in parallel
* Do not execute iib operation on fbc errors
* Better error message when operator item fails due to fbc inconsistency
* Change FBC logic to not call IIB only when ocp_version >=4.13
* Unpin requests-mock version
* Set request threads for uploading signatures
* Reformatted with new tox version
* Added support for FBC operators
* Drop Python2 support
* Use namespace from index image target settings
* Make iib_deprecation_list_url optional target settings

0.10.4 (2022-10-04)
-------------------

* Verify bundles presence
* Do not pass arches in IIB request

0.10.3 (2022-10-04)
-------------------

* Push images to quay in multi-threads
* Added support for hotfix operators
* Use a random filename for the password file in containers
* Fix signatures removal

0.10.2 (2022-08-16)
--------------------
* Use real task ID for tag docker signing
* Get intermediate repo from build details

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
