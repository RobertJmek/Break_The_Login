class AppValidationError(Exception):
    """Excepție custom pentru erori de validare și business logic care pot fi afișate în siguranță clientului."""
    
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def to_dict(self):
        return {"error": self.message}
