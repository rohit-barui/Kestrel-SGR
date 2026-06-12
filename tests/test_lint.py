import unittest
import py_compile
import os

class TestLint(unittest.TestCase):
    def test_core_modules_compile(self):
        core_dir = os.path.join(os.path.dirname(__file__), "..", "core")
        for f in os.listdir(core_dir):
            if f.endswith(".py"):
                py_compile.compile(os.path.join(core_dir, f), doraise=True)

    def test_skills_compile(self):
        skills_dir = os.path.join(os.path.dirname(__file__), "..", "skills")
        for f in os.listdir(skills_dir):
            if f.endswith(".py"):
                py_compile.compile(os.path.join(skills_dir, f), doraise=True)

    def test_server_compiles(self):
        py_compile.compile(os.path.join(os.path.dirname(__file__), "..", "server.py"), doraise=True)
