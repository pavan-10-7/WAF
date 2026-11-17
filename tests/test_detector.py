import unittest

import detector


class DetectorTests(unittest.TestCase):
    def setUp(self):
        detector._model = None
        detector._model_loaded = True  # Rule tests remain independent of training artifacts.

    def test_known_attack_categories(self):
        cases = [
            ({"method": "GET", "path": "/search", "query": "id=1 OR 1=1"}, "sqli"),
            ({"method": "POST", "path": "/comment", "body": "<script>alert(1)</script>"}, "xss"),
            ({"method": "GET", "path": "/file", "query": "name=%2e%2e%2fetc/passwd"}, "traversal"),
        ]
        for request, expected in cases:
            with self.subTest(expected=expected):
                result = detector.detect(request)
                self.assertEqual((result["verdict"], result["attack_type"]), ("block", expected))
                self.assertGreaterEqual(result["score"], 0.0)
                self.assertLessEqual(result["score"], 1.0)

    def test_benign_request(self):
        result = detector.detect({"method": "GET", "path": "/products", "query": "sort=price"})
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(result["attack_type"], "none")

    def test_malformed_input_defaults_safely(self):
        result = detector.detect(None)
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(set(result), {"verdict", "attack_type", "score", "reason"})


if __name__ == "__main__":
    unittest.main()
