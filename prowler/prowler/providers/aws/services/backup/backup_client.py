from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.backup.backup_service import Backup

backup_client = Backup(current_audit_info)
