
from attacks.common import create_session, send_request, display_result


TESTS = [
    {
        "name": "Normal SQLi module access",
        "endpoint": "/vulnerabilities/sqli/",
        "params": {
            "id": "1",
            "Submit": "Submit"
        }
    },
    {
        "name": "Normal XSS module access",
        "endpoint": "/vulnerabilities/xss_r/",
        "params": {
            "name": "Alice",
            "Submit": "Submit"
        }
    },
    {
        "name": "Normal File Inclusion access",
        "endpoint": "/vulnerabilities/fi/",
        "params": {
            "page": "file1.php"
        }
    }
]


def run_benign_tests():
    print("\n[BENIGN] Starting legitimate traffic tests")

    session = create_session()

    passed = 0
    failed = 0

    try:
        for test in TESTS:
            try:
                response = send_request(
                    session=session,
                    endpoint=test["endpoint"],
                    params=test["params"]
                )

                display_result(test["name"], response)

                # Verify that the application returned the
                # requested module instead of redirecting to login.
                successful = (
                    response.status_code == 200
                    and test["endpoint"] in response.url
                )

                if successful:
                    print("[PASS] Legitimate request accepted")
                    passed += 1
                else:
                    print("[FAIL] Unexpected response")
                    failed += 1

            except Exception as error:
                print(f"[ERROR] {test['name']}: {error}")
                failed += 1

    finally:
        session.close()

    print("\n========== BENIGN TEST SUMMARY ==========")
    print(f"Total Tests : {passed + failed}")
    print(f"Passed      : {passed}")
    print(f"Failed      : {failed}")
    print("=========================================")


if __name__ == "__main__":
    run_benign_tests()
