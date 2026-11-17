
from attacks.common import create_session, send_request, display_result


ENDPOINT = "/vulnerabilities/xss_r/"


def run_xss_test():
    print("\n[XSS] Starting local XSS detection test")

    session = create_session()

    # Harmless XSS-pattern test string for WAF detection.
    payload = "<script>alert('WAF_TEST')</script>"

    params = {
        "name": payload,
        "Submit": "Submit"
    }

    response = send_request(
        session=session,
        endpoint=ENDPOINT,
        params=params
    )

    display_result("XSS Detection Test", response)

    if response.status_code == 403:
        print("[PASS] WAF blocked the XSS test payload")
    else:
        print("[FAIL] WAF did not block the XSS test payload")

    session.close()


if __name__ == "__main__":
    run_xss_test()
