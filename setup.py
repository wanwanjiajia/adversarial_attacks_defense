# _*_coding:utf-8 _*_

# @Time      :2020/01/02 17:06

# @Author    : Wanjia Zheng

# @File      :setup.py

# @Software  :PyCharm

import os, sys
from setuptools import setup,find_packages

def read_requirements():
    """Parse requirements from requirements.txt."""
    reqs_path = os.path.join('.', 'requirements.txt')
    with open(reqs_path, 'r') as f:
        requirements = [line.rstrip() for line in f]
    return requirements

setup(
    name="adversarial attacks defense",
    version="0.0.1",
    description="Doctor Research",
    long_description= "./README",
    author="Wanjia, Zheng",
    author_email="banka.cn@gmail.com",
    url='https://github.com/kennethreitz/samplemod',
    license="./LICENSE",
    install_requires=read_requirements(),
    packages=find_packages(exclude=('tests', 'docs'))
)