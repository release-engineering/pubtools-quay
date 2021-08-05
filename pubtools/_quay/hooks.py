import sys

from pubtools.pluggy import pm, hookspec

# Define hooks here for any events which may be of interest for any other
# projects in pubtools-*, or Pub.


@hookspec
def quay_repositories_cleared(repository_ids):
    """Invoked after repositories have been cleared on Quay.

    :param repository_ids: ID of each cleared repository.
    :type repository_ids: list[str]
    """


@hookspec
def quay_repositories_removed(repository_ids):
    """Invoked after repositories have been removed from Quay.

    :param repository_ids: ID of each removed repository.
    :type repository_ids: list[str]
    """


@hookspec
def quay_images_tagged(source_ref, dest_refs):
    """Invoked after tagging image(s) on Quay.

    :param source_ref: Source image reference.
    :type source_ref: str
    :param dest_refs: Destination image reference(s).
    :type dest_refs: list[str]
    """


@hookspec
def quay_images_untagged(untag_refs, lost_refs):
    """Invoked after untagging image(s) on Quay.

    :param untag_refs: Image references for which tags were removed.
    :type untag_refs: list[str]
    :param lost_refs: Image references (by digest) which are no longer reachable from any
                      tag due to the untag operation.
    :type lost_refs: list[str]
    """


@hookspec
def get_cert_key_paths_plugin(server_url):
    """Get location of SSL certificates for a given service.

    If there are multiple hook implementations and multiple values are returned, the first answer
    is considered canonical. The first answer is returned by the hook implementation which was
    registered last. If there are no hook implementations, the fallback strategy is to use
    target settings. The setting names are service dependent, for example for Pyxis
    they are 'pyxis_ssl_cert' and 'pyxis_ssl_key'.

    :param server_url: Service URL.
    :type server_url: str
    :return: Paths to SSL certificate and key.
    :rtype: (str, str)
    """


pm.add_hookspecs(sys.modules[__name__])
