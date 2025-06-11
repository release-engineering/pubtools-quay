from __future__ import annotations

import argparse
import base64
import contextlib
from collections.abc import Iterable
from dataclasses import dataclass, field
import functools
import json
import logging
import os
import pkg_resources
import sys
import textwrap
import time
from typing import Any, Callable, Dict, Generator, cast, Optional, List, Union, Tuple


from concurrent import futures
from concurrent.futures.thread import ThreadPoolExecutor

from io import StringIO
from pubtools.pluggy import pm

from pubtools.tracing import get_trace_wrapper

tw = get_trace_wrapper()
LOG = logging.getLogger("pubtools.quay")

INTERNAL_DELIMITER = "----"
MAX_RETRY_WAIT = 120


@dataclass
class FData:
    """Dataclass for holding data for a function execution.

    Args:
        args (Iterable[Any]): Arguments for the function.
        kwargs (Dict[str, Any]): Keyword arguments for the function.
    """

    args: Iterable[Any]
    kwargs: Dict[str, Any] = field(default_factory=dict)


def run_in_parallel(func: Callable[..., Any], data: List[Any], threads: int = 10) -> Dict[Any, Any]:
    """Run method on data in parallel.

    Args:
        func (function): Function to run on data
        data (list): List of tuples which are used as arguments for the function
    Returns:
        dict: List of result in the same order as data.
    """
    future_results = {}
    results = {}
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_results = {
            executor.submit(func, *data_entry.args, **data_entry.kwargs): n
            for n, data_entry in enumerate(data)
        }
        for future in futures.as_completed(future_results):
            if future.exception() is not None:
                raise cast(BaseException, future.exception())
            results[future_results[future]] = future.result()
    return dict(sorted(results.items(), key=lambda kv: kv[0]))


def setup_arg_parser(args: Dict[Any, Any]) -> argparse.ArgumentParser:
    """
    Set up ArgumentParser with the provided arguments.

    Args:
        args (dict)
            Dictionary of argument aliases and options to be consumed by ArgumentParser.
    Returns:
        (ArgumentParser) Configured instance of ArgumentParser.
    """
    parser = argparse.ArgumentParser()
    arg_groups: Dict[Any, Any] = {}
    for aliases, arg_data in args.items():
        holder = parser
        if "group" in arg_data:
            arg_groups.setdefault(arg_data["group"], parser.add_argument_group(arg_data["group"]))
            holder = arg_groups[arg_data["group"]]
        action = arg_data.get("action")
        if not action and arg_data["type"] == bool:
            action = "store_true"
        kwargs = {
            "help": arg_data.get("help"),
            "required": arg_data.get("required", False),
            "default": arg_data.get("default"),
        }
        if action:
            kwargs["action"] = action
        else:
            kwargs["type"] = arg_data.get("type", "str")
            kwargs["nargs"] = arg_data.get("count")

        holder.add_argument(*aliases, **kwargs)

    return parser


def add_args_env_variables(
    parsed_args: argparse.Namespace, args: Dict[Any, Any]
) -> argparse.Namespace:
    """
    Add argument values from environment variables.

    Args:
        parsed_args ():
            Parsed arguments object.
        args (dict):
            Argument definition.
    Returns:
        Modified parsed arguments object.
    """
    for aliases, arg_data in args.items():
        named_alias = [x.lstrip("-").replace("-", "_") for x in aliases if x.startswith("--")][0]
        if arg_data.get("env_variable"):
            if not getattr(parsed_args, named_alias) and os.environ.get(arg_data["env_variable"]):
                setattr(parsed_args, named_alias, os.environ.get(arg_data["env_variable"]))
    return parsed_args


@contextlib.contextmanager
def capture_stdout() -> Generator[StringIO, None, None]:
    """Capture sys.stdout to stream buffer."""
    old_stdout = sys.stdout
    sys.stdout = new_stdout = StringIO()

    try:
        yield new_stdout
    finally:
        sys.stdout = old_stdout


@contextlib.contextmanager
def setup_entry_point_cli(
    entry_tuple: Tuple[str, str, str],
    name: Optional[str],
    args: List[str],
    environ_vars: Dict[str, Any],
) -> Generator[Callable[[], Any], None, None]:
    """
    Set up an entrypoint as a context manager.

    Args:
        entry_tuple ((str, str, str)):
            Tuple consisting of dependency, category, and entrypoint.
        name: (str):
            Entrypoint name.
        args ([str]):
            Entrypoint arguments.
        environ_vars (dict):
            Env variable names and values to set for the entrypoint.
    """
    orig_environ = os.environ.copy()

    try:
        # First argv element is always the entry point name.
        # For a console_scripts entry point, this will be the same value
        # as if the script was invoked directly. For any other kind of entry point,
        # this value is probably meaningless.
        for key in environ_vars:
            os.environ[key] = environ_vars[key]
        entry_point_func = pkg_resources.load_entry_point(*entry_tuple)
        if args:
            if name:
                func_args = [name]
            else:
                func_args = []
            func_args.extend(args)
            if entry_tuple[1] == "console_scripts":
                yield functools.partial(entry_point_func, func_args)
            else:
                yield functools.partial(entry_point_func, *func_args)
        else:
            yield entry_point_func
    finally:
        os.environ.update(orig_environ)

        to_delete = [key for key in os.environ if key not in orig_environ]
        for key in to_delete:
            del os.environ[key]


def run_entrypoint(
    entry_tuple: Tuple[str, str, str],
    name: Optional[str],
    args: List[str],
    environ_vars: Dict[str, Any],
    capture_out: bool = True,
) -> Any:
    """
    Run an entrypoint function and return its return value.

    Args:
        entry_tuple ((str, str, str)):
            Tuple consisting of dependency, category, and entrypoint.
        name: (str):
            Entrypoint name.
        args ([str]):
            Entrypoint arguments.
        environ_vars (dict):
            Env variable names and values to set for the entrypoint.
        capture_out (bool):
            Whether to capture stdout.

    Returns (str):
        Data returned by the entrypoint.
    """
    raw_args = " ".join([entry_tuple[2]] + args)
    wrapped_lines = textwrap.wrap(
        raw_args, 100, subsequent_indent="  ", break_on_hyphens=False, break_long_words=False
    )

    LOG.info("Running task with arguments:")
    for idx, line in enumerate(wrapped_lines):
        suffix = ""
        if idx != len(wrapped_lines) - 1:
            # shell-style backslash to indicate continuation
            suffix = " \\"
        LOG.info("%s%s", line, suffix)

    with setup_entry_point_cli(entry_tuple, name, args, environ_vars) as entry_func:
        if capture_out:
            with capture_stdout():
                pyret = entry_func()
        else:
            pyret = entry_func()

    return pyret


def get_internal_container_repo_name(external_name: str) -> str:
    """
    Transform a repository name to an internal form in which it exists on Quay.io.

    Expected input format: <namespace>/<product>
    Generated output format: <namespace>----<product>

    NOTE: Repositories without a delimeter "/" may actually exist. In that case, the function
    simply returns the repo without any alterations.

    Args:
        external_name (str):
            External repository name.
    Returns:
        Internal repository name.
    """
    if external_name.count("/") == 0:
        return external_name

    if external_name.count("/") > 1 or external_name[0] == "/" or external_name[-1] == "/":
        raise ValueError(
            "Input repository containing a delimeter should "
            "have the format '<namespace>/<product>'",
            external_name,
        )

    return external_name.replace("/", INTERNAL_DELIMITER)


def get_external_container_repo_name(internal_name: str) -> str:
    """
    Transform a repository name to an external form in which it's visible to customers.

    Expected input format: <namespace>----<product>
    Generated output format: <namespace>/<product>

    NOTE: Repositories without a delimeter "----" may actually exist. In that case, the function
    simply returns the repo without any alterations.

    Args:
        internal_name (str):
            Internal repository name.
    Returns:
        External repository name.
    """
    if internal_name.count(INTERNAL_DELIMITER) == 0:
        return internal_name

    if (
        internal_name.count(INTERNAL_DELIMITER) > 1
        or internal_name.find(INTERNAL_DELIMITER) == 0
        or internal_name.find(INTERNAL_DELIMITER) == len(internal_name) - 4
    ):
        raise ValueError(
            "Input repository containing a delimeter should "
            "have the format '<namespace>----<product>'",
            internal_name,
        )

    return internal_name.replace(INTERNAL_DELIMITER, "/")


def task_status(event: str) -> Dict[str, Dict[str, str]]:
    """Helper function. Expand as necessary."""  # noqa: D401
    return dict(event={"type": event})


def log_step(step_name: str) -> Callable[[Any], Any]:
    """
    Log status for methods which constitute an entire task step.

    Args:
        step_name (str):
            Name of the task step, e.g., "Tag images".
    """
    event_name = step_name.lower().replace(" ", "-")

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        # Add instrumentation trace for all push steps.
        fn = tw.instrument_func(span_name=event_name)(fn)

        @functools.wraps(fn)
        def fn_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                LOG.info("%s: Started", step_name, extra=task_status("%s-start" % event_name))
                ret = fn(*args, **kwargs)
                LOG.info("%s: Finished", step_name, extra=task_status("%s-end" % event_name))
                return ret
            except Exception:
                LOG.error("%s: Failed", step_name, extra=task_status("%s-error" % event_name))
                raise

        return fn_wrapper

    return decorate


def get_pyxis_ssl_paths(target_settings: Dict[str, Any]) -> Tuple[str, str]:
    """
    Get certificate and key paths for Pyxis SSL authentication.

    First attempt is made by invoking the hook implementation 'get_cert_key_paths'.
    If nothing is returned (no hook implementation is registered), fallback on target settings
    values of 'pyxis_ssl_cert' and 'pyxis_ssl_key'. If multiple values are returned (multiple
    hook implementations are registered), take the first response (from the implementation which
    was registered last). Otherwise, raise an error.

    Args:
        target_settings (dict):
            Dictionary containing various task-related settings.
    Returns ((str, str)):
        Paths to Pyxis SSL certificate and key.
    """
    result = pm.hook.get_cert_key_paths(server_url=target_settings["pyxis_server"])
    if result:
        cert, key = result
    elif "pyxis_ssl_cert" not in target_settings or "pyxis_ssl_key" not in target_settings:
        raise ValueError(
            "No key and certificate paths were provided for Pyxis SSL authentication. "
            "Please, either provide hook implementation for 'get_cert_key_paths_plugin' or "
            "specify 'pyxis_ssl_cert' and 'pyxis_ssl_key' in the target settings."
        )
    else:
        cert = target_settings["pyxis_ssl_cert"]
        key = target_settings["pyxis_ssl_key"]

    return (cert, key)


def timestamp() -> str:
    """Return now() timestamp."""
    return str(time.time()).split(".")[0]


def run_with_retries(
    function: Callable[[], Any], message: str, tries: int = 4, wait_time_increase: int = 10
) -> Any:
    """
    Run the specified function until it succeeds or maximum retries are reached.

    Wait time will increase after every retry, up to a point defined by MAX_RETRY_WAIT.

    Args:
        function (callable):
            Function that should be retried. It must be able to run with 0 parameters.
        message (str):
            Message describing the action performed by the function. For example, "tag images".
        tries (int):
            Numbers of times to run the function before giving up.
        wait_time_increase (int):
            Time increase (in seconds) to wait before running the function again. Example (default):
            RUN -> WAIT 0 -> RUN -> WAIT 10 -> RUN -> WAIT 20 -> RUN
    """
    wait_time = 0
    for i in range(tries):
        try:
            result = function()
            if i != 0:
                LOG.info("%s succeeded [try: %s/%s]" % (message, i + 1, tries))
            return result
        except Exception as e:
            if i < tries - 1:
                wait_time = i * wait_time_increase if wait_time < MAX_RETRY_WAIT else MAX_RETRY_WAIT
                LOG.warning(
                    "%s failed. Will retry in %d seconds [try %s/%s]: %s"
                    % (message, wait_time, i + 1, tries, str(e))
                )
                time.sleep(wait_time)
                continue
            LOG.error("%s repeatedly fails" % message)
            raise


def retry(
    message: str, tries: int = 4, wait_time_increase: int = 10
) -> Callable[[Callable[..., Any]], Any]:
    """
    Retry decorated function.

    Args:
        message (str):
            Message describing the action performed by the function. For example, "tag images".
        tries (int):
            Numbers of times to run the function before giving up.
        wait_time_increase (int):
            Time increase (in seconds) to wait before running the function again. Example (default):
            RUN -> WAIT 0 -> RUN -> WAIT 10 -> RUN -> WAIT 20 -> RUN
    """

    def inner_retry(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper_func(*args: Any, **kwargs: Any) -> Any:
            bound = functools.partial(func, *args, **kwargs)
            return run_with_retries(bound, message, tries, wait_time_increase)

        return wrapper_func

    return inner_retry


def parse_index_image(build_details: Any) -> Tuple[str, str, str]:
    """
    Get registry, namespace and repository of a resolved internal index image.

    Args:
        build_details (dict):
            Dictionary of IIB build details.
    Returns ((str, str, str)):
        Registry, namespace, repository of an image.
    """
    image_path = build_details.internal_index_image_copy_resolved.split("@")[0]
    registry, namespace, repo = image_path.split("/")

    return (registry, namespace, repo)


def get_basic_auth(host: str) -> Union[Tuple[Optional[str], Optional[str]], List[str]]:
    """
    Look for container config file for username and password.

    Args:
        host (str):
            Hostname of a container registry.
    Returns ((str, str)):
        Username, password of a registry.
    """
    home_dir = os.path.expanduser("~")
    conf_file = os.path.join(home_dir, ".docker/config.json")
    if os.path.isfile(conf_file):
        with open(conf_file) as f:
            config = json.load(f)
        auth = config.get("auths", {}).get(host, {}).get("auth")
        if auth:
            return base64.b64decode(auth).decode().split(":")
    return None, None


def pyxis_get_repo_metadata(repo: str, target_settings: Dict[str, Any]) -> Any:
    """
    Invoke the 'get-repo-metadata' entrypoint from pubtools-pyxis.

    Args:
        repo (str):
            Repository to get the metadata of.
        target_settings (dict):
            Settings used for setting the values of the entrypoint parameters.

    Returns (dict):
        Parsed response from Pyxis.
    """
    cert, key = get_pyxis_ssl_paths(target_settings)

    args = ["--pyxis-server", target_settings["pyxis_server"]]
    args += ["--pyxis-ssl-crtfile", cert]
    args += ["--pyxis-ssl-keyfile", key]
    args += ["--repo-name", repo]

    env_vars: Dict[Any, Any] = {}
    metadata = run_entrypoint(
        ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-repo-metadata"),
        "pubtools-pyxis-get-repo-metadata",
        args,
        env_vars,
    )
    return metadata


def set_aws_kms_environment_variables(target_settings: Dict[str, Any], profile_name: str) -> None:
    """
    Set environment variables required to use an AWS KMS key.

    The values are set from target settings based on the selected profile. Multiple profiles are
    supported as multiple keys may be used during a push. Following env variables are set:
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION. Missing data in target settings
    will not result in an error. Target settings is expected to be in the following format:
    {
    "aws_kms_credentials": {
        "profile-1": {
            "aws_access_key_id": "id1",
            "aws_secret_access_key": "key1",
            "aws_default_region": "us-east-1"
            },
        "profile-2": {
            "aws_access_key_id": "id2",
            "aws_secret_access_key": "key2",
            "aws_default_region": "us-east-2"
            }
        },
    "other_target_setting":"data"
    }

    Args:
        target_settings (dict):
            Target settings.
        profile_name (str):
            Profile name whose credentials to apply.
    """
    if "aws_kms_credentials" not in target_settings:
        LOG.warning(
            "Target settings are missing the aws_kms_credentials property, "
            "cannot set AWS KMS environment variables"
        )
        return
    if profile_name not in target_settings["aws_kms_credentials"]:
        LOG.warning(f"AWS KMS profile {profile_name} not found in the target settings")
        return

    if "aws_access_key_id" not in target_settings["aws_kms_credentials"][profile_name]:
        LOG.warning(
            "Cannot set AWS KMS environment variable AWS_ACCESS_KEY_ID, "
            f"value missing in profile {profile_name}"
        )
    else:
        os.environ["AWS_ACCESS_KEY_ID"] = target_settings["aws_kms_credentials"][profile_name][
            "aws_access_key_id"
        ]

    if "aws_secret_access_key" not in target_settings["aws_kms_credentials"][profile_name]:
        LOG.warning(
            "Cannot set AWS KMS environment variable AWS_SECRET_ACCESS_KEY, "
            f"value missing in profile {profile_name}"
        )
    else:
        os.environ["AWS_SECRET_ACCESS_KEY"] = target_settings["aws_kms_credentials"][profile_name][
            "aws_secret_access_key"
        ]

    if "aws_default_region" not in target_settings["aws_kms_credentials"][profile_name]:
        LOG.warning(
            "Cannot set AWS KMS environment variable AWS_DEFAULT_REGION, "
            f"value missing in profile {profile_name}"
        )
    else:
        os.environ["AWS_DEFAULT_REGION"] = target_settings["aws_kms_credentials"][profile_name][
            "aws_default_region"
        ]
