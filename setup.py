#from distutils.core import setup
from setuptools import setup

from pip.req import parse_requirements

install_reqs = parse_requirements("requirements.txt", session=False)
reqs = [str(ir.req) for ir in install_reqs]


setup(
    name='ProtocolDetector',
    version='1.0',
    packages=['ProtocolDetector'],
    url='https://github.com/jpalanco/ProtocolDetector',
    license='MIT',
    author='jpalanco',
    author_email='jose.palanco@drainware.com',
    description='',
    install_requires=reqs,
    package_data={'ProtocolDetector': ['rules/*.yar']},
    entry_points={
        'console_scripts': [
            'ProtocolDetector=ProtocolDetector.__main__:main',
        ]}
)
