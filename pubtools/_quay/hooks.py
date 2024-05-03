import sys
from typing import List

from pubtools.pluggy import pm, hookspec

# Define hooks here for any events which may be of interest for any other
# projects in pubtools-*, or Pub.


@hookspec
def quay_repositories_cleared(repository_ids: List[str]) -> None:
    """Invoked after repositories have been cleared on Quay.

    :param repository_ids: ID of each cleared repository.
    :type repository_ids: list[str]
    """


@hookspec
def quay_repositories_removed(repository_ids: List[str]) -> None:
    """Invoked after repositories have been removed from Quay.

    :param repository_ids: ID of each removed repository.
    :type repository_ids: list[str]
    """


@hookspec
def quay_images_tagged(source_ref: str, dest_refs: List[str]) -> None:
    """Invoked after tagging image(s) on Quay.

    :param source_ref: Source image reference.
    :type source_ref: str
    :param dest_refs: Destination image reference(s).
    :type dest_refs: list[str]
    """


@hookspec
def quay_images_untagged(untag_refs: List[str], lost_refs: List[str]) -> None:
    """Invoked after untagging image(s) on Quay.

    :param untag_refs: Image references for which tags were removed.
    :type untag_refs: list[str]
    :param lost_refs: Image references (by digest) which are no longer reachable from any
                      tag due to the untag operation.
    :type lost_refs: list[str]
    """


pm.add_hookspecs(sys.modules[__name__])
