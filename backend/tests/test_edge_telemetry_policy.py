"""Static guard on the shipped ingress policy; actual Nginx is tested in CI."""
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


def test_cloud_ingress_avoids_unredacted_request_archives():
    source=(ROOT/"infra/terraform/modules/kernel-platform/ingress.tf").read_text()
    access=re.findall(r"access_logs\s*\{([^}]+)\}",source)
    assert len(access)==1 and re.search(r"enabled\s*=\s*false",access[0])
    assert re.findall(r"sampled_requests_enabled\s*=\s*(\w+)",source)==["false"]*3
    assert re.findall(r"cloudwatch_metrics_enabled\s*=\s*(\w+)",source)==["true"]*3
    # Existing log archives are preserved; this must not delete their resource.
    assert 'resource "aws_s3_bucket" "alb_logs"' in source
