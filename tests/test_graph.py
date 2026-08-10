import unittest
from core.graph import IdentityGraph

class TestIdentityGraph(unittest.TestCase):
    def setUp(self):
        self.graph = IdentityGraph()

    def test_add_entity(self):
        self.graph.add_entity("u1", "user", {"name": "Alice"})
        e = self.graph.get_entity("u1")
        self.assertEqual(e["type"], "user")
        self.assertEqual(e["properties"]["name"], "Alice")

    def test_add_relationship(self):
        self.graph.add_entity("u1", "user")
        self.graph.add_entity("d1", "device")
        self.graph.add_relationship("u1", "d1", "owns")
        neighbors = self.graph.get_neighbors("u1")
        self.assertEqual(len(neighbors), 1)
        self.assertEqual(neighbors[0]["id"], "d1")

    def test_query_path(self):
        self.graph.add_entity("a", "entity")
        self.graph.add_entity("b", "entity")
        self.graph.add_entity("c", "entity")
        self.graph.add_relationship("a", "b", "connects")
        self.graph.add_relationship("b", "c", "connects")
        paths = self.graph.query_path("a", "c")
        self.assertEqual(len(paths), 1)
        self.assertEqual(len(paths[0]), 2)

    def test_query_path_no_route(self):
        self.graph.add_entity("a", "entity")
        self.graph.add_entity("b", "entity")
        paths = self.graph.query_path("a", "b")
        self.assertEqual(paths, [])

    def test_query_path_missing_entity(self):
        # Querying with an entity that was never added returns no paths
        self.graph.add_entity("a", "entity")
        self.assertEqual(self.graph.query_path("missing", "a"), [])
        self.assertEqual(self.graph.query_path("a", "missing"), [])

    def test_get_neighbors_bidirectional(self):
        self.graph.add_entity("u1", "user")
        self.graph.add_entity("d1", "device")
        self.graph.add_relationship("u1", "d1", "uses")
        self.assertEqual(len(self.graph.get_neighbors("d1")), 1)
        self.assertEqual(len(self.graph.get_neighbors("u1")), 1)

if __name__ == "__main__":
    unittest.main()
