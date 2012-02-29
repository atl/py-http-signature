from setuptools import setup, find_packages

setup(
    name='http_signature',
    version='0.1',
    description="Simple secure signing for HTTP requests",
    long_description="Simple secure signing for HTTP requests using the Joyent http-signature specification",
    classifiers=[
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Environment :: Web Environment",
    ],
    keywords='twitter,stream',
    author='Adam Lindsay',
    author_email='a.lindsay+github@gmail.com',
    url='http://github.com/atl/py-http-signature',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=['setuptools'],
)
