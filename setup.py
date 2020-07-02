from setuptools import setup

setup(
    name="composer",
    version="0.1",
    py_modules=["composer"],
    include_package_data=True,
    install_requires=[
        "click",
        "docker",
        "requests_oauthlib",
        "pyyaml",
        "flask",
        "halo",
        "github3.py",
    ],
    extras_require={"dev": ["rope", "ipython"],},
    entry_points="""
        [console_scripts]
        composer=composer:cli
    """,
)
