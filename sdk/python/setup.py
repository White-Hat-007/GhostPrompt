from setuptools import setup, find_packages

setup(
    name="ghostprompt",
    version="1.0.0",
    description="GhostPrompt SDK - The Real-Time Prompt Injection Firewall",
    author="GhostPrompt",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.24.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)
