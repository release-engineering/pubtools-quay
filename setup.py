# -*- coding: utf-8 -*-

"""setup.py"""

import os
import re
import sys

# import pkg_resources
import sys
from setuptools import setup, find_namespace_packages


def read_content(filepath):
    with open(filepath) as fobj:
        return fobj.read()


classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: Implementation :: CPython",
    "Programming Language :: Python :: Implementation :: PyPy",
]


def building_rpm():
    """True when running within RPM build environment, which tweaks
    the build a little."""
    return "RPM_PACKAGE_VERSION" in os.environ


def get_requirements():
    """
    Transform a list of requirements so that they are usable by older pip (9.0.0), and newer pip

    Regex extracts name and url from a tox-compatible format, and replaces it with only a name
    (which will be combined with dependency_links) or with PEP-508 compatible dependency.
    """
    with open("requirements.txt") as f:
        reqs = f.read().splitlines()

    # If we are building an RPM, we don't have pip available, and we want
    # to use the 'name + dependency_link' style
    if building_rpm():
        reqs = sorted(list(set(reqs)))
        pip_ersion = [0, 0, 0]
    else:
        import pip

        pip_version = [int(i) for i in pip.__version__.split(".")]

    reqs = [req for req in reqs if req != ""]
    for i in range(len(reqs)):
        if pip_version < [19, 0, 0]:
            reqs[i] = re.sub(r"-e .*#egg=(.*)-.*", r"\1", reqs[i])
        else:
            reqs[i] = re.sub(r"-e (.*#egg=(.*)-.*)", r"\2 @ \1", reqs[i])

    return reqs


def get_dependency_links():
    """
    Extracts only depenency links for the dependency_links in older versions of pip.
    """
    with open("requirements.txt") as f:
        reqs = f.read().splitlines()
    dependency_links = []
    for req in reqs:
        link = re.subn(r"-e (.*#egg=.*-.*)", r"\1", req)
        if link[1] == 1:
            dependency_links.append(link[0])

    return dependency_links


long_description = read_content("README.rst") + read_content(
    os.path.join("docs/source", "CHANGELOG.rst")
)

extras_require = {"reST": ["Sphinx"]}
if os.environ.get("READTHEDOCS", None):
    extras_require["reST"].append("recommonmark")

setup(
    name="pubtools-quay",
    version="0.36.0",
    description="Pubtools-quay",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    author="Lubomir Gallovic",
    author_email="lgallovi@redhat.com",
    url="https://github.com/release-engineering/pubtools-quay",
    classifiers=classifiers,
    python_requires=">=3.6",
    packages=find_namespace_packages(where="src"),
    package_dir={"": "src"},
    data_files=[],
    install_requires=get_requirements(),
    dependency_links=get_dependency_links(),
    entry_points={
        "console_scripts": [
            "pubtools-quay-tag-image = pubtools._quay.tag_images:tag_images_main",
            "pubtools-quay-merge-manifest-list = "
            "pubtools._quay.merge_manifest_list:merge_manifest_list_main",
            "pubtools-quay-untag = pubtools._quay.untag_images:untag_images_main",
            "pubtools-quay-remove-repo = pubtools._quay.remove_repo:remove_repositories_main",
            "pubtools-quay-clear-repo = pubtools._quay.clear_repo:clear_repositories_main",
        ],
        "target": [
            "push-docker = pubtools._quay.push_docker:mod_entry_point",
            "tag-docker = pubtools._quay.tag_docker:mod_entry_point",
            "iib-add-bundles = pubtools._quay.iib_operations:iib_add_entrypoint",
            "iib-remove-operators = pubtools._quay.iib_operations:iib_remove_entrypoint",
            "iib-build-from-scratch = pubtools._quay.iib_operations:iib_from_scratch_entrypoint",
            "iib-add-deprecations = pubtools._quay.iib_operations:iib_add_deprecations_entrypoint",
        ],
    },
    include_package_data=True,
    extras_require=extras_require,
    tests_require=["tox"]
)
