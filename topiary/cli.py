import ast
import importlib
import os
import re
import sys
from typing import Dict, Iterable, List, Set

import pip_api
import toml


def not_stdlib_modules(modname: str, site_pkg_mods: List[str]) -> bool:
    """Determines whether or not a module is part of the python standard library.
    """
    print(f'modname: {modname}')
    #try:
    #    spec = importlib.util.find_spec(modname)
    #    print(f'module spec: {spec}, parent: {spec.parent}')
    #    return '/site-packages/' in spec.origin
    #except (AttributeError, ModuleNotFoundError):
    #    return True
    return modname in site_pkg_mods


def extract_pkg_imports(filepath: str, site_pkg_mods: List[str]) -> List[str]:
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

    return [m.split('.')[0] for m in mods if not_stdlib_modules(m.split('.')[0], site_pkg_mods)]


def get_venv_dist_pkgs() -> Dict[str, str]:
    venv_lib_path = os.path.join(os.environ['VIRTUAL_ENV'], 'lib')
    py_dir = os.listdir(venv_lib_path)[0]
    site_packages_path = os.path.join(venv_lib_path, py_dir, 'site-packages')
    dist_info_dirs = [d for d in os.listdir(site_packages_path) if d.endswith('.dist-info')]
    return {d.split('-', 1)[0]: os.path.join(site_packages_path, d) for d in dist_info_dirs}


def make_mod_to_pkg_map(pkgs: Iterable[str]) -> Dict[str, str]:
    pkg_set = set(pkgs)
    pkg_set.remove('python')
    #dists = {name: pkg for name, pkg in pip_api.installed_distributions(local=False).items() if name in pkg_set}
    dists = get_venv_dist_pkgs()
    print(dists)
    #dist_set = set(dists.keys())
    #if any(pkg not in dist_set for pkg in pkg_set):
    #    raise Exception(f'some pkgs in pyproject.toml are not installed: {pkg_set - dist_set}')
    mod_to_pkg_map = {}
    for name, path in dists.items():
        #top_level_filename = f'{d.location}/{d.name.replace("-", "_")}-{d.version}.dist-info/top_level.txt'
        try:
            top_level_filename = f'{path}/top_level.txt'
            with open(top_level_filename) as f:
                top_level_mod = f.read().rstrip('\n')
                mod_to_pkg_map[top_level_mod] = name
        except FileNotFoundError:
            pass
    print(mod_to_pkg_map)
    return mod_to_pkg_map


def write_new_pyproject(old_filename: str, new_filename: str, unnecessary_deps: Set[str]):
    """Write a new pyproject.toml file without the unnecessary dependencies.

    Parses and writes the file manually, without toml.dump(), to preserve order & minimize diffs.
    """
    
    def is_deps_block_start(line: str):
        # Supports poetry only for now
        # NOTE: Does not support PEP 0631 at this time!
        return line == '[tool.poetry.dependencies]\n'

    def is_deps_block_end(line: str):
        return line.startswith('[')

    DEP_RE = re.compile(r'^[-_a-zA-Z0-9]+')
    def dep_is_unnecessary(line: str, unnecessary_deps: Set[str]):
        if match := DEP_RE.match(line):
            return match.group(0) in unnecessary_deps

    with open(old_filename) as f_in, open(new_filename, 'w') as f_out:
        in_deps_block = False
        for line in f_in:
            if not in_deps_block or not dep_is_unnecessary(line, unnecessary_deps):
                f_out.write(line)
            if in_deps_block and is_deps_block_end(line):
                in_deps_block = False
            elif is_deps_block_start(line):
                in_deps_block = True


def is_python_file(filename: str):
    return filename.endswith('.py')


def is_test(filename: str):
    # TODO: read pytest config file for testfile patterns
    return 'test' in filename


def main():
    # TODO proper argparse
    in_place = len(sys.argv) > 1 and sys.argv[1] == '-i'

    filepaths = [os.path.join(d, fp) for d, _, fps in os.walk('.') for fp in fps]
    code_filepaths = [fp for fp in filepaths if is_python_file(fp) and not is_test(fp)]
    print(code_filepaths)

    pyproj = toml.load('pyproject.toml')
    pyproj_deps = pyproj['tool']['poetry']['dependencies']


    dep_pkgs = set(pkg.replace('-', '_') for pkg in pyproj_deps.keys())
    print(f'dep pkgs: {dep_pkgs}')
    mod_to_pkg_map = make_mod_to_pkg_map(dep_pkgs)

    imported_modules = set(imp for fp in code_filepaths for imp in extract_pkg_imports(fp, list(mod_to_pkg_map.keys())))
    print(f'imported modules: {imported_modules}')
    imported_pkgs = set(pkg for mod, pkg in mod_to_pkg_map.items() if mod in imported_modules)
    print(f'imp pkgs: {imported_pkgs}')

    unnecessary_pkgs = dep_pkgs - imported_pkgs
    unnecessary_pkgs.discard('python')  # python is always necessary but never imported
    write_new_pyproject('pyproject.toml', 'pyproject.toml.new', unnecessary_pkgs)

    if in_place:
        os.replace('pyproject.toml.new', 'pyproject.toml')
