class AppError(Exception):
    def __init__(self, message: str, *, status_code: int = 400, code: str = "app_error") -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


class ExternalServiceError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(
            message,
            status_code=503,
            code="external_service_error",
        )


class ValidationError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=422, code="validation_error")
