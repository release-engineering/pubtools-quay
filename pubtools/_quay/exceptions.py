class ManifestTypeError(Exception):
    """Occurs when an incorrect manifest type is encountered."""


class RegistryAuthError(Exception):
    """Occurs when registry authentication encounters an issue."""


class BadPushItem(Exception):
    """Occurs when a bad push item is being processed."""


class InvalidTargetSettings(Exception):
    """Occurs when required target setting is missing or has an incorrect value."""


class InvalidRepository(Exception):
    """Occurs when a repository hasn't passed its validation checks."""


class SigningError(Exception):
    """Occurs when there was an issue in the container signing process done by RADAS."""
