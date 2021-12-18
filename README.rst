=======
topiary
=======

``topiary`` is a tool for trimming down unnecessary dependencies from ``pyproject.toml``.
Right now it only supports poetry projects.

Installation
============

Run the following in the enclosing python environment (not directly in the project's poetry virtualenv):

.. code-block:: console

   $ pip install git+https://github.com/jjsloboda/topiary.git

Usage
=====

.. code-block:: console

   $ cd my_project_root
   $ poetry run topiary

Will create a new ``pyproject.toml.new`` that is a copy of ``pyproject.toml`` with unnecessary package dependencies trimmed out.

.. code-block:: console

   $ cd my_project_root
   $ poetry run topiary -i

Will trim out the unnecessary package dependencies in ``pyproject.toml`` in place.
