
from distutils.core import setup

import toml

pyproj = toml.load('pyproject.toml')

readme_str = 'TODO'


setup(
        name=pyproj['tool.poetry']['name'],
        version=pyproj['tool.poetry']['version'],
        description=pyproj['tool.poetry']['description'],
        author=' '.join(pyproj['tool.poetry']['authors'][0].split()[:2]),
        author_email=pyproj['tool.poetry']['authors'][0].split()[3][1:-1],
        url=f'https://github.com/jjsloboda/{pyproj["tool.poetry"]["name"]}',
        packages=['topiary'],
        license=pyproj['tool.poetry']['license'],
        long_description=readme_str,
        python_requires=pyproj['tool.poetry.dependencies']['python'],
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Intended Audience :: Developers',
            'License :: OSI Approved :: MIT License',
            'Operating System :: OS Independent',
            'Programming Language :: Python',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.10',
            'Programming Language :: Python :: Implementation :: CPython',
        ],
)
