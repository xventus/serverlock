from setuptools import setup
import os
import sys

_here = os.path.abspath(os.path.dirname(__file__))

if sys.version_info[0] < 3:
    with open(os.path.join(_here, 'README.rst')) as f:
        long_description = f.read()
else:
    with open(os.path.join(_here, 'README.rst'), encoding='utf-8') as f:
        long_description = f.read()

version = {}
with open(os.path.join(_here, 'serverlockpackage', 'version.py')) as f:
    exec(f.read(), version)

setup(
    name='serverlockpackage',
    version=version['__version__'],
    description=('Server lock packagee.'),
    long_description=long_description,
    author='Petr Vanek',
    author_email='petr@fotoventus.cz',
    url='',
    license='MPL-2.0',
    packages=['serverlockpackage'],
    install_requires=['cryptography'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Science/Research',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6'],
    )
