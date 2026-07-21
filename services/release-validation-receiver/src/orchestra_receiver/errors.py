class ReceiverError(Exception):
    def __init__(self, code: str, status: int, message: str):
        super().__init__(message)
        self.code = code
        self.status = status


class DispatchError(Exception):
    def __init__(self, code: str, message: str, http_status: int | None = None):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


class RetryableDispatchError(DispatchError):
    pass


class IndeterminateDispatchError(DispatchError):
    pass


class PermanentDispatchError(DispatchError):
    pass
