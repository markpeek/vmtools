from setuptools import setup, Extension, find_packages

setup(name='vmtools',
      version='0.1',
      description="Minimal set of VMware tools",
      author="Mark Peek",
      author_email="mark@peek.org",
      license="New BSD license",
      ext_modules=[Extension('_vmt', ['vmtmodule.c'])],
      py_modules = ['vmtools',],
      entry_points = {
          'console_scripts': [
              'vmtools = vmtools:main',
          ],
      }
)
