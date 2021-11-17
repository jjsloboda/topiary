import ast
import importlib
import sys

import toml


def from_site_packages(modname: str) -> bool:
    return '/site-packages/' in importlib.util.find_spec(modname).origin


def extract_modules(filename: str):
    with open(filepath) as f:
        tree = ast.parse(f.read())

    mods = []
    for node in tree.body:
        if type(node) == ast.Import:
            mods.extend(alias.name for alias in node.names)
        elif type(node) == ast.ImportFrom:
            if node.level == 0:
                mods.append(node.module)

    return set(m for m in mods if from_site_packages(m))


def main():
    # TODO proper argparse
    filepaths = sys.argv[1:]

    pyproj = toml.load('pyproject.toml')
    dep_modules = set(pyproj['tools.poetry.dependencies'].keys())

    imported_modules = [extract_modules(fp) for fp in filepaths]
    print(f'imported modules: {imported_modules}')

    dep_modules = extract_deps()
    print(f'dep modules: {dep_modules}')

    unnecessary_modules = dep_modules - imported_modules
    for dep in dep_modules:
        if dep in unnecessary_modules:
            del pyproj['tools.poetry.dependencies'][dep]

    print(toml.dumps(pyproj))
    toml.dump('pyproject.toml.new')


main()
