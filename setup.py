import setuptools

from cripto import __version__ as version

setuptools.setup(     
     name="cripto-tools",     
     version=version,
     python_requires=">=3.6",   
     py_modules=["cripto"],
     author="Rafael Perazzo",
     install_requires=['cffi','argon2-cffi','pycryptodome','python-gnupg','argon2-cffi-bindings'],
)