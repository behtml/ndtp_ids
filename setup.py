from setuptools import setup, find_packages

setup(
    name="ndtp_ids",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "flask",
        "scapy",
        "scikit-learn",
        "numpy",
    ],
    python_requires=">=3.8",
)