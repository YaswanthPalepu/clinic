#!/usr/bin/env python3
"""Production health check script for Clinical BERT API"""

# Standard library imports
import asyncio
import json
import sys

# import time
from typing import Any, Dict

# Third party imports
import httpx


async def comprehensive_health_check(base_url: str) -> Dict[str, Any]:
    """Perform comprehensive health check"""

    async with httpx.AsyncClient(timeout=30) as client:
        results = {"overall_status": "unknown", "checks": {}}

        try:
            # Basic health check
            response = await client.get(f"{base_url}/health")
            results["checks"]["health"] = {
                "status": "healthy" if response.status_code == 200 else "unhealthy",
                "response_time_ms": response.elapsed.total_seconds() * 1000,
            }

            # Test prediction endpoint
            test_response = await client.post(
                f"{base_url}/predict",
                json={"sentence": "The patient denies chest pain."},
            )
            results["checks"]["prediction"] = {
                "status": "healthy"
                if test_response.status_code == 200
                else "unhealthy",
                "response_time_ms": test_response.elapsed.total_seconds() * 1000,
            }

            # Determine overall status
            all_healthy = all(
                check.get("status") == "healthy" for check in results["checks"].values()
            )
            results["overall_status"] = "healthy" if all_healthy else "unhealthy"

        except Exception as e:
            results["checks"]["error"] = {"status": "unhealthy", "error": str(e)}
            results["overall_status"] = "unhealthy"

        return results


async def main():
    # Standard library imports
    import argparse

    parser = argparse.ArgumentParser(description="Clinical BERT API Health Check")
    parser.add_argument("--url", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--json", action="store_true", help="Output JSON")

    args = parser.parse_args()

    results = await comprehensive_health_check(args.url)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        status_emoji = {"healthy": "PASS", "unhealthy": "FAIL", "unknown": "UNKNOWN"}
        overall = results["overall_status"]
        print(f"\n{status_emoji.get(overall, 'UNKNOWN')} Overall Status: {overall.upper()}")

        for check_name, check_result in results["checks"].items():
            status = check_result.get("status", "unknown")
            emoji = status_emoji.get(status, "UNKNOWN")
            print(f"  {emoji} {check_name.title()}: {status}")

            if "response_time_ms" in check_result:
                print(f"    Response Time: {check_result['response_time_ms']:.2f}ms")

    # Exit with error code if unhealthy
    if results["overall_status"] != "healthy":
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
