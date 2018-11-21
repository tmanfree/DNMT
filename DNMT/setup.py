import setuptools


NAME = "dnmt"
DESCRIPTION = "Direct Network Management Tool"
URL = "https://github.com/tmanfree/DNMT"
EMAIL = "tmanfree@hotmail.com"
AUTHOR = "Thomas Mandzie"
VERSION = "0.0.1"


with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name=NAME,
    version=VERSION,
    author=AUTHOR,
    author_email=EMAIL,
    description=DESCRIPTION,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url=URL,
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)