import hashlib
import unittest

from lib import generate_ntlmv2_response, check_ntlmv2_response, random_byte_sequence


class Test(unittest.TestCase):
    def test_random_bytes(self):
        a = random_byte_sequence(8)

        # check correct answer
        self.assertTrue(isinstance(a, bytes))
        self.assertEqual(len(a), 8)

        # check that answers are different
        b = random_byte_sequence(8)
        self.assertNotEqual(a, b)

    def test_correct_response(self):
        """Test incorrect case"""

        password = "password"
        password_hash = hashlib.new("md4", password.encode("utf-16le")).digest()
        username = "username"
        domain = "domain"

        server_challenge = random_byte_sequence(8)

        response = generate_ntlmv2_response(
            username, password, domain, server_challenge
        )
        self.assertIsNotNone(response)

        self.assertTrue(
            check_ntlmv2_response(
                password_hash, username, domain, response, server_challenge
            )
        )

    def test_incorrect(self):
        """Test incorrect password"""

        password = "password"
        incorrect_pasword = "INCORRECT_PASSWORD"
        password_hash = hashlib.new("md4", password.encode("utf-16le")).digest()
        username = "username"
        domain = "domain"

        server_challenge = random_byte_sequence(8)

        response = generate_ntlmv2_response(
            username, incorrect_pasword, domain, server_challenge
        )
        self.assertIsNotNone(response)

        self.assertFalse(
            check_ntlmv2_response(
                password_hash, username, domain, response, server_challenge
            )
        )


if __name__ == "__main__":
    unittest.main()
