from setuptools import setup

from cripto import __version__ as version

setup(     
     name="cripto-tools",     
     version=version,
     python_requires=">=3.6",   
     py_modules=["cripto"],
     author="Rafael Perazzo",
     install_requires=['pycryptodome','argon2-cffi','python-gnupg'],
)