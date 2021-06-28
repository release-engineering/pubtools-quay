import logging


class Logger(object):
    """Logging helper class."""

    def __init__(self):
        """Init the logger instance."""
        self.logger = logging.getLogger("pubtools.quay")

    def log_info(self, *args, **kwargs):
        """Log message with info level."""
        self.logger.log(logging.INFO, *args, **kwargs)

    def log_error(self, *args, **kwargs):
        """Log message with error level."""
        self.logger.log(logging.ERROR, *args, **kwargs)

    def log_warning(self, *args, **kwargs):
        """Log message with warning level."""
        self.logger.log(logging.WARNING, *args, **kwargs)

    def log_debug(self, *args, **kwargs):
        """Log message with debug level."""
        self.logger.log(logging.DEBUG, *args, **kwargs)


def task_status(event):
    """Log task status.

    Expand as necessary.
    """
    return dict(event={"type": event})


def log_jsonl(step_name):
    """Log task status before and after decorated method.

    For methods which constitute an entire task step.

    :param step_name: Name of the task step, e.g., "Tag images".
    """
    event_name = step_name.lower().replace(" ", "-")
    logger = logging.getLogger("pubtools.quay")

    def decorate(fn):
        def fn_wrapper(*args, **kwargs):
            try:
                logger.info("%s: Started", step_name, extra=task_status("%s-start" % event_name))
                ret = fn(*args, **kwargs)
                logger.info("%s: Finished", step_name, extra=task_status("%s-end" % event_name))
                return ret
            except Exception:
                logger.error("%s: Failed", step_name, extra=task_status("%s-error" % event_name))
                raise

        return fn_wrapper

    return decorate
