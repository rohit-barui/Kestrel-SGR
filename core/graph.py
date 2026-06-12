from typing import Dict, List, Any, Optional, Set

class IdentityGraph:
    def __init__(self):
        self.entities: Dict[str, Dict[str, Any]] = {}
        self.relationships: Set[tuple] = set()

    def add_entity(self, entity_id: str, entity_type: str, properties: Optional[Dict[str, Any]] = None):
        self.entities[entity_id] = {"id": entity_id, "type": entity_type, "properties": properties or {}}

    def add_relationship(self, from_id: str, to_id: str, label: str):
        if from_id in self.entities and to_id in self.entities:
            self.relationships.add((from_id, to_id, label))

    def get_entity(self, entity_id: str) -> Optional[Dict[str, Any]]:
        return self.entities.get(entity_id)

    def query_path(self, from_id: str, to_id: str) -> List[List[tuple]]:
        if from_id not in self.entities or to_id not in self.entities:
            return []
        paths = []
        visited = set()
        def dfs(current: str, target: str, path: List[tuple]):
            if current == target:
                paths.append(path[:])
                return
            visited.add(current)
            for f, t, l in self.relationships:
                if f == current and t not in visited:
                    path.append((f, t, l))
                    dfs(t, target, path)
                    path.pop()
            visited.discard(current)
        dfs(from_id, to_id, [])
        return paths

    def get_neighbors(self, entity_id: str) -> List[Dict[str, Any]]:
        result = []
        for f, t, l in self.relationships:
            if f == entity_id and t in self.entities:
                result.append({**self.entities[t], "relation": l})
            if t == entity_id and f in self.entities:
                result.append({**self.entities[f], "relation": l})
        return result
