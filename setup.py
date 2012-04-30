from setuptools import setup, find_packages

with open('README.rst') as file:
    long_description = file.read()

setup(
    name='http_signature',
    version='0.1.2',
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
    install_requires=['pycrypto', 'ssh'],
)
