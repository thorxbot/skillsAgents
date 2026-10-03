"""Build hook: bundle ``data/``, ``schemas/`` and ``references/`` into wheels as ``ipa_analyzer/_<name>``.

Source-tree and editable installs read these directories from the skill root directly
(see ``ipa_analyzer.util.paths.resource_dir``).
"""
import pathlib
import shutil

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPy(build_py):
    def run(self):
        super().run()
        root = pathlib.Path(__file__).resolve().parent
        for name in ("data", "schemas", "references"):
            src = root / name
            if src.is_dir():
                shutil.copytree(src, pathlib.Path(self.build_lib) / "ipa_analyzer" / ("_" + name),
                                dirs_exist_ok=True)


setup(cmdclass={"build_py": BuildPy})
