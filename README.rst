=======
topiary
=======

``topiary`` is a tool for trimming down unnecessary dependencies from ``pyproject.toml``.
Right now it only supports poetry projects.

Installation
============

.. code-block:: shell
   $ pip install topiary

Usage
=====

.. code-block:: shell
   $ cd my_project_root
   $ topiary

Will create a new ``pyproject.toml.new`` that is a copy of ``pyproject.toml`` with unnecessary package dependencies trimmed out.

.. code-block:: shell
   $ cd my_project_root
   $ topiary -i

Will trim out the unnecessary package dependencies in ``pyproject.toml`` in place.
