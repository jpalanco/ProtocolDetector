from setuptools import setup, find_packages

from pip._internal.req import parse_requirements

reqs = []
for ir in parse_requirements("requirements.txt", session=False):
    try:
        reqs.append(str(ir.req))
    except:
        reqs.append(str(ir.requirement))

setup(
    name='ProtocolDetector',
    version='1.0.13',
    packages=find_packages(),
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
