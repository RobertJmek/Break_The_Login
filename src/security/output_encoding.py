import html

class OutputEncoding:
    """
    Security Control: Output Encoding (Anti-XSS).
    Asigură neutralizarea datelor introduse de utilizatori înainte de a fi afișate.
    """
    
    @staticmethod
    def encode_text(text):
        """
        Transformă caracterele periculoase (<, >, &, ", ') în entități HTML sigure.
        Exemplu: <script> devine &lt;script&gt;
        """
        if not isinstance(text, str):
            return text
            
        # quote=True escapează inclusiv ghilimelele simple și duble
        return html.escape(text, quote=True)

    @staticmethod
    def sanitize_dict(data):
        """
        Parcurge un dicționar și aplică Output Encoding pe toate valorile de tip text.
        Extrem de util înainte de a returna răspunsuri JSON către Frontend din Backend API.
        """
        if not data:
            return data
            
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = OutputEncoding.encode_text(value)
            elif isinstance(value, dict):
                sanitized[key] = OutputEncoding.sanitize_dict(value)
            elif isinstance(value, list):
                # Sanitizează listele de string-uri
                sanitized[key] = [OutputEncoding.encode_text(item) if isinstance(item, str) else item for item in value]
            else:
                sanitized[key] = value
                
        return sanitized
