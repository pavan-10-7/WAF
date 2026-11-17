
from attacks.common import create_session, send_request, display_result


ENDPOINT = "/vulnerabilities/xss_r/"


def run_xss_test():
    print("\n[XSS] Starting local XSS test")

    session = create_session()

    # Harmless marker for testing reflected input handling.
    payload = "WAF_XSS_TEST_MARKER"

    params = {
        "name": payload,
        "Submit": "Submit"
    }

    response = send_request(
        session=session,
        endpoint=ENDPOINT,
        params=params
    )

    display_result("XSS Reflection Test", response)

    reflected = payload in response.text

    print(f"Marker reflected: {reflected}")

    session.close()


if __name__ == "__main__":
    run_xss_test()
