from setuptools import setup

from cripto import __version__ as version

with open('requirements.txt', encoding='utf-8') as f:
    requirements = f.read().splitlines()

setup(     
     name="cripto-tools",     
     version=version,
     python_requires=">=3.6",   
     py_modules=["cripto"],
     author="Rafael Perazzo",
     install_requires=requirements,
)