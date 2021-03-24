class ManifestTypeError(Exception):
    """Occurres when an incorrect manifest type is encountered."""


class RegistryAuthError(Exception):
    """Occurres when registry authentication encounters an issue."""


class BadPushItem(Exception):
    """Occurres when a bad push item is being proccessed."""


class InvalidTargetSettings(Exception):
    """Occurres when required target setting is missing or has an incorrect value."""


class InvalidRepository(Exception):
    """Occurres when a repository hasn't passed its validation checks."""


class SigningError(Exception):
    """Occurs when there was an issue in the container signing process done by RADAS."""
