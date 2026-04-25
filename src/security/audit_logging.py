import logging
import json
import threading
from data.audit_repo import AuditRepo

def _save_to_db_background(user_id, action, resource, resource_id, ip_address, log_data_str):
    """Task rulat in fundal pentru a nu bloca request-ul HTTP."""
    try:
        AuditRepo.log_action(user_id, action, resource, resource_id, ip_address)
    except Exception as e:
        # Fallback de siguranță salvat TOT în format JSON
        critical_log = {
            "event_type": "CRITICAL_AUDIT_FAILURE",
            "error": str(e),
            "failed_event": json.loads(log_data_str)
        }
        logging.critical(json.dumps(critical_log))


def log_security_event(user_id, action, resource, resource_id, ip_address):
    """Security Control: Audit Logging.
    Înregistrează evenimentul local (JSON) și în DB (Threaded).
    """
    
    # 1. Anti Log-Injection (CRLF)
    log_data = {
        "event_type": "AUDIT",
        "user_id": user_id,
        "action": action,
        "resource": resource,
        "resource_id": resource_id,
        "ip_address": ip_address
    }
    log_data_str = json.dumps(log_data)
    
    # Scrierea în fișier e instantanee

    logging.info(log_data_str)
    
    # 2. Optimizare Latență: Trimitem salvarea în DB pe un thread separat (Fire & Forget)
    
    thread = threading.Thread(
        target=_save_to_db_background,
        args=(user_id, action, resource, resource_id, ip_address, log_data_str)
    )
    # Rulăm ca daemon thread ca să nu țină serverul blocat la închidere
    thread.daemon = True 
    thread.start()
