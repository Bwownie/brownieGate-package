from setuptools import setup, find_packages

setup(
    name='browniegate',
    version='0.1.9',
    packages=find_packages(),
    description='A secure API client for handling encrypted payloads and authentication.',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    author='Jethro Mackay',
    author_email='jethrolovespancake@gmail.com',
    url='https://github.com/Bwownie/brownieGate-package',
    license='MIT',
    install_requires=[
        'requests>=2.31.0',
        'cryptography>=42.0.0'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
)