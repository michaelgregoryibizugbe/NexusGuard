from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="nexusguard",
    version="1.0.0",
    author="Security Team",
    author_email="security @nexusguard.io",
    description="Advanced IPS/IDS with beautiful TUI and Web GUI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/nexusguard",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.5.0",
        "rich>=13.7.0",
        "textual>=0.44.1",
        "flask>=3.0.0",
        "flask-socketio>=5.3.5",
        "scikit-learn>=1.3.2",
        "PyYAML>=6.0.1",
    ],
    entry_points={
        "console_scripts": [
            "nexusguard=nexusguard.cli:main",
        ],
    },
    include_package_data=True,
)
