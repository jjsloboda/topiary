import ast
import importlib
import sys
from typing import List, Set

import toml


def not_stdlib_modules(modname: str) -> bool:
    """Determines whether or not a module is part of the python standard library.
    """
    print(f'modname: {modname}')
    try:
        return '/site-packages/' in importlib.util.find_spec(modname).origin
    except (AttributeError, ModuleNotFoundError):
        return True


def extract_pkg_imports(filepath: str) -> List[str]:
    """Given a path to a python file, return a list of all modules imported at the top level.
    """
    with open(filepath) as f:
        tree = ast.parse(f.read())

    mods = []
    for node in tree.body:
        if type(node) == ast.Import:
            mods.extend(alias.name for alias in node.names)
        elif type(node) == ast.ImportFrom:
            if node.level == 0:
                mods.append(node.module)

    return [m for m in mods if not_stdlib_modules(m)]


def write_new_pyproject(old_filename: str, new_filename: str, unnecessary_deps: Set[str]):
    """Write a new pyproject.toml file without the unnecessary dependencies.

    Parses and writes the file manually, without toml.dump(), to preserve order & minimize diffs.
    """
    
    def is_deps_block_start(line: str):
        # Supports poetry only for now
        return line == '[tool.poetry.dependencies]\n'

    def is_deps_block_end(line: str):
        return line == '\n'

    DEP_RE = re.compile(r'^[-_a-z]+')
    def dep_is_unnecessary(line: str, unnecessary_deps: Set[str]):
        if match := DEP_RE.match(line):
            return match.group(0) in unnecessary_deps

    with open(old_filename) as f_in, open(new_filename, 'w') as f_out:
        in_deps_block = False
        for line in f_in:
            if in_deps_block and is_deps_block_end(line):
                in_deps_block = False
            elif is_deps_block_start(line):
                in_deps_block = True
            elif not in_deps_block or not dep_is_unnecessary(line, unnecessary_deps):
                f_out.write(line)


def main():
    # TODO proper argparse
    filepaths = sys.argv[1:]

    pyproj = toml.load('pyproject.toml')
    pyproj_deps = pyproj['tool']['poetry']['dependencies']

    imported_modules = set(imp for fp in filepaths for imp in extract_pkg_imports(fp))
    print(f'imported modules: {imported_modules}')

    dep_modules = set(pyproj_deps.keys())
    print(f'dep modules: {dep_modules}')

    unnecessary_modules = dep_modules - imported_modules
    unnecessary_modules.discard('python')  # python is always necessary but never imported
    write_new_pyproject('pyproject.toml', 'pyproject.toml.new', unnecessary_deps)


main()
