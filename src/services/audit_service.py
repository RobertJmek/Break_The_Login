from data.audit_repo import AuditRepo
from security.exceptions import AppValidationError

class AuditService:
    """Business Module: Audit Viewer (Manager only)."""
    
    @staticmethod
    def view_audit_logs(user_role, limit: int = 50, offset: int = 0):
        """
        Extrage log-urile de audit paginate pentru a fi afișate Managerului.
        """
        if user_role != 'MANAGER':
            raise AppValidationError("Acces respins la loguri. Doar un manager le poate vizualiza.")

        return AuditRepo.get_all_logs(limit=limit, offset=offset)
