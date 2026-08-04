class WardenError(Exception):
    """Base exception for all Warden SDK errors."""
    pass

class ToolNotTrustedError(WardenError):
    """Raised when a tool is blocked or not trusted by Warden policy."""
    pass

class AuthError(WardenError):
    """Raised when authentication (API Key validation) fails."""
    pass

class APIError(WardenError):
    """Raised when the Warden API returns an error or is unreachable."""
    pass
