import argparse
import json
import os


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
            arg_groups.setdefault(
                arg_data["group"], parser.add_argument_group(arg_data["group"])
            )
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
        named_alias = [
            x.lstrip("-").replace("-", "_") for x in aliases if x.startswith("--")
        ][0]
        if arg_data.get("env_variable"):
            if not getattr(parsed_args, named_alias) and os.environ.get(
                arg_data["env_variable"]
            ):
                setattr(
                    parsed_args, named_alias, os.environ.get(arg_data["env_variable"])
                )
    return parsed_args


def send_umb_message(
    urls, props, cert, topic, body=None, client_key=None, ca_cert=None
):
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
