from typing import Any


class IdentityGraph:
    def __init__(self):
        self.entities: dict[str, dict[str, Any]] = {}
        self.relationships: set[tuple] = set()

    def add_entity(self, entity_id: str, entity_type: str, properties: dict[str, Any] | None = None):
        self.entities[entity_id] = {"id": entity_id, "type": entity_type, "properties": properties or {}}

    def add_relationship(self, from_id: str, to_id: str, label: str):
        if from_id in self.entities and to_id in self.entities:
            self.relationships.add((from_id, to_id, label))

    def get_entity(self, entity_id: str) -> dict[str, Any] | None:
        return self.entities.get(entity_id)

    def query_path(self, from_id: str, to_id: str) -> list[list[tuple]]:
        if from_id not in self.entities or to_id not in self.entities:
            return []
        paths = []
        visited = set()
        def dfs(current: str, target: str, path: list[tuple]):
            if current == target:
                paths.append(path[:])
                return
            visited.add(current)
            for src, tgt, lbl in self.relationships:
                if src == current and tgt not in visited:
                    path.append((src, tgt, lbl))
                    dfs(tgt, target, path)
                    path.pop()
            visited.discard(current)
        dfs(from_id, to_id, [])
        return paths

    def get_neighbors(self, entity_id: str) -> list[dict[str, Any]]:
        result = []
        for src, tgt, lbl in self.relationships:
            if src == entity_id and tgt in self.entities:
                result.append({**self.entities[tgt], "relation": lbl})
            if tgt == entity_id and src in self.entities:
                result.append({**self.entities[src], "relation": lbl})
        return result
