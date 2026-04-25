from data.audit_repo import AuditRepo
from security.exceptions import AppValidationError

class AuditService:
    """Business Module: Audit Viewer (Manager only)."""
    
    @staticmethod
    def view_audit_logs(user_role):
        """
        Extrage toate log-urile de audit pentru a fi afișate Managerului.
        Orice filtrare, paginare sau formatare a datelor (Business Logic) 
        va fi implementată aici înainte de a le trimite spre Backend API.
        """

        if user_role != 'MANAGER':
            raise AppValidationError("Acces respins la loguri. Doar un manager le poate vizualiza.")
        
        logs = AuditRepo.get_all_logs()
        return logs
