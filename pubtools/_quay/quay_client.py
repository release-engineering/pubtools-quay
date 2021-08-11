import hashlib
import json
import logging
import requests
import re
from requests.packages.urllib3.util.retry import Retry

# Unfortunately, version of 'six' available on RHEL 6 doesn't cover this redirect
try:
    import urllib2 as request
except ImportError:  # pragma: no cover
    from urllib import request

from .exceptions import ManifestTypeError, RegistryAuthError
from .quay_session import QuaySession

LOG = logging.getLogger("pubtools.quay")


class QuayClient:
    """Class for performing Docker HTTP API operations with the Quay registry."""

    MANIFEST_LIST_TYPE = "application/vnd.docker.distribution.manifest.list.v2+json"
    MANIFEST_V2S2_TYPE = "application/vnd.docker.distribution.manifest.v2+json"

    def __init__(self, username, password, host=None):
        """
        Initialize.

        Args:
            username (str):
                Quay username.
            password (str):
                Quay password.
            host (str):
                Quay registry URL.
        """
        self.username = username
        self.password = password
        self.session = QuaySession(hostname=host, api="docker")

    def get_manifest(self, image, raw=False, manifest_list=False):
        """
        Get manifest of a given image along with its type.

        Manifest type order of preference is:
        1. manifest list
        2. V2S2 manifest
        3. anything else

        Args:
            image (str):
                Image for which to get the manifest list.
            raw (bool):
                Whether to return the manifest as raw JSON.
            manifest_list (bool):
                Whether to only return a manifest list and raise an exception otherwise.
        Returns (dict|str):
            Image manifest
                Raises:
            ManifestTypeError:
                When the image doesn't have a manifest list.
        """
        repo, ref = self._parse_and_validate_image_url(image)
        endpoint = "{0}/manifests/{1}".format(repo, ref)

        # request 'Content-Type' to be manifest list
        kwargs = {"headers": {"Accept": QuayClient.MANIFEST_LIST_TYPE}}
        response = self._request_quay("GET", endpoint, kwargs)
        if manifest_list and response.headers["Content-Type"] != QuayClient.MANIFEST_LIST_TYPE:
            raise ManifestTypeError("Image {0} doesn't have a manifest list".format(image))

        # We asked for ML but received neither ML nor V2S2. Let's ask again for V2S2
        if (
            response.headers["Content-Type"] != QuayClient.MANIFEST_LIST_TYPE
            and response.headers["Content-Type"] != QuayClient.MANIFEST_V2S2_TYPE
        ):
            kwargs = {"headers": {"Accept": QuayClient.MANIFEST_V2S2_TYPE}}
            response = self._request_quay("GET", endpoint, kwargs)

        if raw:
            return response.text
        else:
            return response.json()

    def get_manifest_digest(self, image):
        """
        Get manifest of the specified image and calculate its digest by hashing it.

        Args:
            image (str):
                Image address for which to calculate the digest.
        Returns (str):
            Manifest digest of the image.
        """
        manifest = self.get_manifest(image, raw=True)
        # SHA 256 is pretty much the standard for container images
        hasher = hashlib.sha256()
        hasher.update(manifest.encode("utf-8"))
        digest = hasher.hexdigest()

        return "sha256:{0}".format(digest)

    def upload_manifest(self, manifest, image, raw=False):
        """
        Upload manifest to a specified image.

        All manifest types are supported (manifest, manifest list).

        Args:
            manifest (dict):
                Manifest to be uploaded.
            image (str):
                Image address to upload the manifest to.
            raw (bool):
                Whether the given manifest is a string (raw) or a Python dictionary
        """
        repo, ref = self._parse_and_validate_image_url(image)
        endpoint = "{0}/manifests/{1}".format(repo, ref)

        if raw:
            manifest_type = json.loads(manifest)["mediaType"]
            kwargs = {
                "headers": {"Content-Type": manifest_type},
                "data": manifest,
            }
        else:
            manifest_type = manifest["mediaType"]
            kwargs = {
                "headers": {"Content-Type": manifest_type},
                "data": json.dumps(manifest, sort_keys=True, indent=4),
            }
        self._request_quay("PUT", endpoint, kwargs)

    def get_repository_tags(self, repository, raw=False):
        """
        Get tags of a provided repository.

        Args:
            repository (str):
                Repository whose tags should be gathered (expected format namespce/repo).
            raw (bool):
                Whether the given manifest is a string (raw) or a Python dictionary
        Returns (list):
            Tags which the repository contains.
        """
        endpoint = "{0}/tags/list".format(repository)
        response = self._request_quay("GET", endpoint)
        tags = response.json()

        while "Link" in response.headers:
            # next page response has format '</v2/....>; rel="next"'
            matches = re.findall('</v2/(.+?)>; rel="next"', response.headers["Link"])
            if len(matches) != 1:
                raise ValueError(
                    "Could not extract next page URL from response '{0}'".format(
                        response.headers["Link"]
                    )
                )
            response = self._request_quay("GET", matches[0])
            tags["tags"].extend(response.json()["tags"])

        if raw:
            return json.dumps(tags)
        else:
            return tags

    def _request_quay(self, method, endpoint, kwargs={}):
        """
        Perform a Docker HTTP API request on Quay registry. Handle authentication.

        Args:
            method (str):
                REST API method of the request (GET, POST, PUT, DELETE).
            endpoint (str):
                Endpoint of the request.
            kwargs (dict):
                Optional arguments to add to the Request object.
        Returns (Response):
            Request library's Response object.
        Raises:
            HTTPError: When the request returned an error status.
        """
        r = self.session.request(method, endpoint, **kwargs)
        # 401 is tolerated as Bearer token might need to be generated
        if r.status_code >= 400 and r.status_code < 600 and r.status_code != 401:
            r.raise_for_status()
        if r.status_code == 401:
            LOG.debug("Unauthorized request, attempting to authenticate.")
            self._authenticate_quay(r.headers)
        else:
            return r

        r = self.session.request(method, endpoint, **kwargs)
        r.raise_for_status()

        return r

    def _authenticate_quay(self, headers):
        """
        Attempt to perform an authentication with registry's authentication server.

        Once authentication is complete, add the token to the Session object.
        Specifics can be found at https://docs.docker.com/registry/spec/auth/token/

        Args:
            headers (dict):
                Headers of the 401 response received from the registry.
        Raises:
            RegistryAuthError:
                When there's an issue with the authentication procedure.
        """
        if "WWW-Authenticate" not in headers:
            raise RegistryAuthError(
                "'WWW-Authenticate' is not in the 401 response's header. "
                "Authentication cannot continue."
            )
        if "Bearer " not in headers["WWW-Authenticate"]:
            raise RegistryAuthError(
                "Different than the Bearer authentication type was requested. "
                "Only Bearer is supported."
            )

        # parse header to get a dictionary
        params = request.parse_keqv_list(
            request.parse_http_list(headers["WWW-Authenticate"][len("Bearer ") :])  # noqa: E203
        )
        host = params.pop("realm")
        session = requests.Session()
        retry = Retry(
            total=3,
            read=3,
            connect=3,
            backoff_factor=2,
            status_forcelist=set(range(500, 512)),
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        # Make an authentication request to the specified realm with the provided REST parameters.
        # Basic username + password authentication is expected.
        r = session.get(host, params=params, auth=(self.username, self.password))
        r.raise_for_status()

        if "token" not in r.json():
            raise RegistryAuthError("Authentication server response doesn't contain a token.")
        self.session.set_auth_token(r.json()["token"])

    def _parse_and_validate_image_url(self, image):
        """
        Extract image repository + reference from an image and validate its data.

        Args:
            image (str):
                A quay.io image.
        Returns (str, str):
            Tuple containing image repository (without base URL) and reference.
        Raises:
            ValueError:
                If image doesn't contain the expected data.
        """
        url_parts = image.split("/")
        if "@" in url_parts[-1]:
            remainder, ref = url_parts[-1].split("@")
        elif ":" in url_parts[-1]:
            remainder, ref = url_parts[-1].split(":")
        else:
            raise ValueError("Neither tag nor digest were found in the image")

        # Skip base URL and get last part of URL without reference
        repo = "/".join(url_parts[1:-1] + [remainder])
        return (repo, ref)
