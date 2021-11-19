import ast
import importlib
import sys
from typing import List

import toml


def from_site_packages(modname: str) -> bool:
    print(f'modname: {modname}')
    return '/site-packages/' in importlib.util.find_spec(modname).origin


def extract_imports(filepath: str) -> List[str]:
    with open(filepath) as f:
        tree = ast.parse(f.read())

    mods = []
    for node in tree.body:
        if type(node) == ast.Import:
            mods.extend(alias.name for alias in node.names)
        elif type(node) == ast.ImportFrom:
            if node.level == 0:
                mods.append(node.module)

    return [m for m in mods if from_site_packages(m)]


def main():
    # TODO proper argparse
    filepaths = sys.argv[1:]

    pyproj = toml.load('pyproject.toml')
    pyproj_deps = pyproj['tool']['poetry']['dependencies']

    imported_modules = set(imp for fp in filepaths for imp in extract_imports(fp))
    print(f'imported modules: {imported_modules}')

    dep_modules = set(pyproj_deps.keys())
    print(f'dep modules: {dep_modules}')

    unnecessary_modules = dep_modules - imported_modules
    unnecessary_modules.pop('python', None)
    for dep in dep_modules:
        if dep in unnecessary_modules:
            del pyproj_deps[dep]

    print(toml.dumps(pyproj))
    with open('pyproject.toml.new', 'w') as f:
        toml.dump(pyproj, f)


main()
