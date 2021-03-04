# Compatibility helpers for caplog in py2 vs py3.
#
# Note: delete this file when python2 is dropped!


class CapturelogWrapper(object):
    """A wrapper for pytest-catchlog fixture (for python2.6).

    This allows many tests to use caplog's modern API without having
    to add branches to care about py2 support.

    Note that this class is not guaranteed to make everything behave
    identically though. You should update it if your test needs
    something missing here.
    """

    def __init__(self, legacy):
        """
        Initilize.

        Args:
            legacy:
                Legacy caplog fixture.
        """
        self._legacy = legacy

        # These are identical methods between old and new APIs
        self.set_level = legacy.set_level
        self.at_level = legacy.at_level

    @property
    def messages(self):
        """
        Property in caplog, does not exist at all in legacy fixture.

        This property gives the interpolated log messages only, without
        applying the logger's configured formatter (e.g. "something happened"
        and not "[ERROR] something happened").
        """
        return [rec.getMessage() for rec in self.records]

    # These are identical properties between old and new APIs
    handler = property(lambda self: self._legacy.handler)
    text = property(lambda self: self._legacy.text)
    records = property(lambda self: self._legacy.records)
