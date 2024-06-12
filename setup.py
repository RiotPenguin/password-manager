from setuptools import setup, find_packages

setup(
    name='password_manager',
    version='0.1',
    py_modules=['password_manager'],
    install_requires=[
        'cryptography',
    ],
    entry_points='''
        [console_scripts]
        password-manager=password_manager:main
    ''',
)
