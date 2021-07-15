import argparse
import contextlib
import functools
import json
import logging
import os
import pkg_resources
import sys
import textwrap

from six import StringIO

LOG = logging.getLogger("pubtools.quay")

INTERNAL_DELIMITER = "----"


def setup_arg_parser(args):
    """
    Set up ArgumentParser with the provided arguments.

    Args:
        args (dict)
            Dictionary of argument aliases and options to be consumed by ArgumentParser.
    Returns:
        (ArgumentParser) Configured instance of ArgumentParser.
    """
    parser = argparse.ArgumentParser()
    arg_groups = {}
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


def add_args_env_variables(parsed_args, args):
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


def send_umb_message(urls, props, cert, topic, body=None, client_key=None, ca_cert=None):
    """
    Send a UMB message.

    Args:
        urls ([str]):
            URLs to send the message to.
        props (dict):
            Message properties dictionary.
        cert (str):
            Path to certificate for SSL authentication.
        topic (str):
            Topic to send the message to.
        body (str):
            Body of the message.
        client_key (str):
            Path to a private key for accessing the certificate.
        ca_cert (str):
            Path to CA certificate.
    """
    from rhmsg.activemq.producer import AMQProducer

    producer = AMQProducer(
        urls=urls,
        certificate=cert,
        private_key=client_key,
        topic=topic,
        trusted_certificates=ca_cert,
    )
    if not body:
        body = json.dumps(props).encode("utf-8")
    producer.send_msg(props, body)


@contextlib.contextmanager
def capture_stdout():
    """Capture sys.stdout to stream buffer."""
    old_stdout = sys.stdout
    sys.stdout = new_stdout = StringIO()

    try:
        yield new_stdout
    finally:
        sys.stdout = old_stdout


@contextlib.contextmanager
def setup_entry_point_cli(entry_tuple, name, args, environ_vars):
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
    orig_argv = sys.argv[:]
    orig_environ = os.environ.copy()

    try:
        # First argv element is always the entry point name.
        # For a console_scripts entry point, this will be the same value
        # as if the script was invoked directly. For any other kind of entry point,
        # this value is probably meaningless.
        sys.argv = [name]
        sys.argv.extend(args)
        for key in environ_vars:
            os.environ[key] = environ_vars[key]
        entry_point_func = pkg_resources.load_entry_point(*entry_tuple)
        yield entry_point_func
    finally:
        sys.argv = orig_argv[:]
        os.environ.update(orig_environ)

        to_delete = [key for key in os.environ if key not in orig_environ]
        for key in to_delete:
            del os.environ[key]


def run_entrypoint(entry_tuple, name, args, environ_vars):
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
        with capture_stdout():
            pyret = entry_func()

    return pyret


def get_internal_container_repo_name(external_name):
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


def get_external_container_repo_name(internal_name):
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


def task_status(event):
    """Helper function. Expand as necessary."""  # noqa: D401
    return dict(event={"type": event})


def log_step(step_name):
    """
    Log status for methods which constitute an entire task step.

    Args:
        step_name (str):
            Name of the task step, e.g., "Tag images".
    """
    event_name = step_name.lower().replace(" ", "-")

    def decorate(fn):
        @functools.wraps(fn)
        def fn_wrapper(*args, **kwargs):
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
