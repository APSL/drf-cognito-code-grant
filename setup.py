#!/usr/bin/env python3

from io import open

from setuptools import find_packages, setup


def readall(path):
    with open(path, encoding="utf-8") as fp:
        return fp.read()


setup(
    name="cognito_code_grant",
    version="1.0.16",
    description="A middleware and a set of handlers to handle "
    "Code Grant authentication with Cognito",
    long_description=readall("README.md"),
    long_description_content_type="text/markdown",
    author="STITCH (Aleksey Panov, Mario Brito, Gaston Lucero, Daniel Hengeveld)",
    author_email="panovitch@gmail.com",
    license="MIT",
    packages=find_packages(exclude=("tests.*", "tests")),
    python_requires=">=3.5",
    install_requires=["Django>=1.11", "djangorestframework>=3.0", "requests", "python-jose", "cryptography"],
    include_package_data=True,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 2.2",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
    ],
)
