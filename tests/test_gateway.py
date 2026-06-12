import unittest
from core.gateway import Gateway

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

if __name__ == "__main__":
    unittest.main()
