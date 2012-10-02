from setuptools import setup, find_packages
import versioneer
versioneer.versionfile_source = 'http_signature/_version.py'
versioneer.versionfile_build = 'http_signature/_version.py'
versioneer.tag_prefix = 'v' # tags are like 1.2.0
versioneer.parentdir_prefix = 'http_signature-' # dirname like 'myproject-1.2.0'

with open('README.rst') as file:
    long_description = file.read()
with open('CHANGES.rst') as file:
    long_description += '\n\n' + file.read()

setup(
    name='http_signature',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="Simple secure signing for HTTP requests using http-signature",
    long_description=long_description,
    classifiers=[
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP",
        "Environment :: Web Environment",
        "Topic :: Internet :: WWW/HTTP :: Site Management",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Development Status :: 3 - Alpha",
    ],
    keywords='http,cryptography,web,joyent',
    author='Adam T. Lindsay',
    author_email='a.lindsay+github@gmail.com',
    url='https://github.com/atl/py-http-signature',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=True,
    install_requires=['pycrypto'],
)
