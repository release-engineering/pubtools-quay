import hashlib
import json
import logging
import requests
import re
from urllib3.util.retry import Retry
from urllib import request
import threading
from typing import Any, cast, Dict, List, Tuple, Optional, Union, Mapping

from .exceptions import ManifestTypeError, RegistryAuthError, ManifestNotFoundError
from .quay_session import QuaySession
from .types import ManifestList, Manifest

LOG = logging.getLogger("pubtools.quay")


class QuayClient:
    """Class for performing Docker HTTP API operations with the Quay registry."""

    MANIFEST_LIST_TYPE = "application/vnd.docker.distribution.manifest.list.v2+json"
    MANIFEST_V2S2_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
    MANIFEST_V2S1_TYPE = "application/vnd.docker.distribution.manifest.v1+json"
    MANIFEST_OCI_LIST_TYPE = "application/vnd.oci.image.index.v1+json"
    MANIFEST_OCI_V2S2_TYPE = "application/vnd.oci.image.manifest.v1+json"

    def __init__(
        self, username: Optional[str], password: Optional[str], host: Optional[str] = None
    ) -> None:
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
        self.host = host
        self.thread_local = threading.local()

    @property
    def session(self) -> Union[Any, QuaySession]:
        """Create QuaySession object per thread."""
        if not hasattr(self.thread_local, "session"):
            self.thread_local.session = QuaySession(hostname=self.host, api="docker")
        return self.thread_local.session

    def get_manifest(
        self,
        image: str,
        raw: bool = False,
        media_type: Optional[str] = None,
        return_headers: bool = False,
    ) -> Union[ManifestList, Manifest, str, Tuple[str, Mapping[str, str]]]:
        """
        Get manifest of given media type.

        Args:
            image (str):
                Image for which to get the manifest list.
            raw (bool):
                Whether to return the manifest as raw JSON.
            manifest_list (bool):
                Whether to only return a manifest list and raise an exception otherwise.
            media_type (str):
                Can be application/vnd.docker.distribution.manifest.list.v2+json,
                application/vnd.docker.distribution.manifest.v2+json,
                application/vnd.docker.distribution.manifest.v1+json,
                application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json
                or None indicating which manifest type is requested. If it's None,
                manifest list is prefered, but if v2s2 is returned instead, v2s2
                is returned as final result. If neither is found, same order is attempted with
                OCI type images.
        Returns (dict|str):
            Image manifest
        Raises:
            ManifestTypeError:
                When the image doesn't return the requested manifest type.
            ValueError:
                If Manifest list and V2S1 manifest are requested at the same time.
        """
        repo, ref = self._parse_and_validate_image_url(image)
        endpoint = "{0}/manifests/{1}".format(repo, ref)

        if media_type:
            kwargs = {"headers": {"Accept": media_type}}
            response = self._request_quay("GET", endpoint, kwargs)

            # text/plain may be returned for V2S1 by our CDN
            if (
                response.headers["Content-Type"] != media_type
                and "text/plain" not in response.headers["Content-Type"]
            ):
                raise ManifestTypeError(
                    "Image {0} doesn't have a {1} manifest".format(image, media_type)
                )
            if raw:
                if not return_headers:
                    return str(response.text)
                else:
                    return (str(response.text), response.headers)
            else:
                return cast(ManifestList, response.json())

        # If type is not specified, try to get manifests in this order
        # If somehow none of these match, we'll accept whatever we got
        for manifest_type in (
            QuayClient.MANIFEST_LIST_TYPE,
            QuayClient.MANIFEST_V2S2_TYPE,
            QuayClient.MANIFEST_OCI_LIST_TYPE,
            QuayClient.MANIFEST_OCI_V2S2_TYPE,
            QuayClient.MANIFEST_V2S1_TYPE,
        ):
            kwargs = {"headers": {"Accept": manifest_type}}
            response = self._request_quay("GET", endpoint, kwargs)

            if response.headers["Content-Type"] == manifest_type:
                break

        if raw:
            return response.text
        else:
            return cast(ManifestList, response.json())

    def get_manifest_digest(self, image: str, media_type: Optional[str] = None) -> str:
        """
        Get manifest of the specified image and calculate its digest by hashing it.

        Args:
            image (str):
                Image address for which to calculate the digest.
            media_type (str):
                Type of manifest can be application/vnd.docker.distribution.manifest.v2+json
                or application/vnd.docker.distribution.manifest.v1+json
        Returns (str):
            Manifest digest of the image.
        """
        try:
            manifest = cast(str, self.get_manifest(image, raw=True, media_type=media_type))
        except requests.exceptions.HTTPError as exc:
            if exc.response.status_code == 404:
                raise ManifestNotFoundError()
            else:
                raise exc
        # SHA 256 is pretty much the standard for container images
        hasher = hashlib.sha256()
        hasher.update(manifest.encode("utf-8"))
        digest = hasher.hexdigest()

        return "sha256:{0}".format(digest)

    def upload_manifest(
        self, manifest: Union[ManifestList, str], image: str, raw: bool = False
    ) -> None:
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
            manifest_type = json.loads(cast(str, manifest)).get(
                "mediaType", QuayClient.MANIFEST_V2S1_TYPE
            )
            kwargs = {
                "headers": {"Content-Type": manifest_type},
                "data": cast(str, manifest),
            }
        else:
            manifest_type = cast(Manifest, manifest).get("mediaType", QuayClient.MANIFEST_V2S1_TYPE)
            kwargs = {
                "headers": {"Content-Type": manifest_type},
                "data": json.dumps(cast(ManifestList, manifest), sort_keys=True, indent=4),
            }
        self._request_quay("PUT", endpoint, kwargs)

    def get_repository_tags(
        self, repository: str, raw: bool = False
    ) -> Union[str, Dict[str, List[str]]]:
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
            return cast(Dict[str, List[str]], tags)

    def _request_quay(
        self, method: str, endpoint: str, kwargs: Dict[Any, Any] = {}
    ) -> requests.Response:
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

    def _authenticate_quay(self, headers: Union[Dict[Any, Any], Mapping[str, Any]]) -> None:
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
        r = session.get(
            host, params=params, auth=(self.username or "", self.password or ""), timeout=10
        )
        r.raise_for_status()

        if "token" not in r.json():
            raise RegistryAuthError("Authentication server response doesn't contain a token.")
        self.session.set_auth_token(r.json()["token"])

    def _parse_and_validate_image_url(self, image: str) -> Tuple[str, str]:
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
