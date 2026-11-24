import tempfile
from pathlib import Path
import unittest
from rns_web_auth import Sessions, TTL, COOKIE, cookie_header, read_cookie


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.users = {'testuser': 'fixed-test-credential-hash'}
        self.path = Path(self.directory.name) / 'sessions.sqlite3'
        self.sessions = Sessions(self.path, self.users)

    def tearDown(self):
        self.directory.cleanup()

    def test_cookie_security_and_host_prefix(self):
        header = cookie_header('not-a-real-session')
        self.assertTrue(header.startswith('__Host-'))
        for attribute in ['Path=/', 'Secure', 'HttpOnly', 'SameSite=Strict', 'Max-Age=604800']:
            self.assertIn(attribute, header)
        self.assertNotIn('Domain=', header)

    def test_expiry_and_tampering(self):
        token, expiry = self.sessions.issue('testuser', now=1000)
        self.assertEqual(expiry, 1000 + TTL)
        self.assertIsNotNone(self.sessions.verify(token, now=1001))
        self.assertIsNone(self.sessions.verify(token, now=expiry))
        self.assertIsNone(self.sessions.verify(token + 'x', now=1001))
        self.assertIsNone(self.sessions.verify('x' * 43, now=1001))
        self.assertIsNone(self.sessions.verify(None))

    def test_logout_revokes_server_side(self):
        token, _ = self.sessions.issue('testuser', now=1000)
        self.sessions.revoke(token)
        self.assertIsNone(self.sessions.verify(token, now=1001))

    def test_new_login_rotates_old_session(self):
        old, _ = self.sessions.issue('testuser', now=1000)
        new, _ = self.sessions.issue('testuser', old_token=old, now=1001)
        self.assertNotEqual(old, new)
        self.assertIsNone(self.sessions.verify(old, now=1002))
        self.assertIsNotNone(self.sessions.verify(new, now=1002))

    def test_tokens_are_hashed_and_persist_across_restart(self):
        token, _ = self.sessions.issue('testuser', now=1000)
        self.assertNotIn(token.encode(), self.path.read_bytes())
        restarted = Sessions(self.path, self.users)
        self.assertIsNotNone(restarted.verify(token, now=1001))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_password_change_or_removed_user_revokes_sessions(self):
        token, _ = self.sessions.issue('testuser', now=1000)
        self.users['testuser'] = 'changed-test-credential-hash'
        self.assertIsNone(self.sessions.verify(token, now=1001))
        del self.users['testuser']
        self.assertIsNone(self.sessions.verify(token, now=1001))

    def test_unknown_user_cannot_create_session(self):
        with self.assertRaises(ValueError):
            self.sessions.issue('unknown')

    def test_cookie_parsing_and_explicit_deletion(self):
        self.assertEqual(read_cookie(f'{COOKIE}=example; unrelated=value'), 'example')
        self.assertIsNone(read_cookie(None))
        self.assertIsNone(read_cookie('x' * 8193))
        self.assertIn('Max-Age=0', cookie_header(max_age=0))


if __name__ == '__main__':
    unittest.main()
