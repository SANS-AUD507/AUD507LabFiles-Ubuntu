from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.cloudfront.cloudfront_service import CloudFront

cloudfront_client = CloudFront(current_audit_info)
