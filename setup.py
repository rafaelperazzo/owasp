import setuptools

from cripto import __version__ as version

setuptools.setup(     
     name="cripto-tools",     
     version=version,
     python_requires=">=3.6",   
     packages=["cripto"],
     author="Rafael Perazzo",
)