import unittest

from core.gateway import Gateway, rollback_noop


class TestGateway(unittest.TestCase):
    def setUp(self):
        self.gateway = Gateway()

    def test_record_and_commit(self):
        self.gateway.record(action="noop", params={}, rollback=lambda p: None)
        self.assertFalse(self.gateway._committed)
        self.gateway.commit()
        self.assertTrue(self.gateway._committed)
        # after commit log should be cleared
        self.assertEqual(len(self.gateway._log), 0)

    def test_rollback_execution(self):
        called = []
        def rb(p):
            called.append(p)
        self.gateway.record(action="test", params={"x": 1}, rollback=rb)
        self.gateway.record(action="test2", params={"y": 2}, rollback=rb)
        self.gateway.rollback()
        # rollbacks should be called in reverse order
        self.assertEqual(called, [{"y": 2}, {"x": 1}])
        self.assertFalse(self.gateway._committed)
        self.assertEqual(len(self.gateway._log), 0)

    def test_record_after_commit_raises(self):
        self.gateway.commit()
        with self.assertRaises(RuntimeError):
            self.gateway.record(action="late", params={}, rollback=lambda p: None)

    def test_rollback_after_commit_is_noop(self):
        called = []
        self.gateway.record(action="a", params={}, rollback=lambda p: called.append(1))
        self.gateway.commit()
        self.gateway.rollback()
        self.assertEqual(called, [])

    def test_rollback_error_does_not_raise(self):
        def bad_rollback(p):
            raise RuntimeError("rollback failure")
        def good_rollback(p):
            called.append("good")
        called = []
        self.gateway.record(action="bad", params={}, rollback=bad_rollback)
        self.gateway.record(action="good", params={}, rollback=good_rollback)
        # Should not raise; both rollbacks attempted in reverse order
        self.gateway.rollback()
        self.assertEqual(called, ["good"])
        self.assertEqual(len(self.gateway._log), 0)

    def test_rollback_noop(self):
        # rollback_noop should not raise
        rollback_noop({})
        self.assertTrue(True)

if __name__ == "__main__":
    unittest.main()
