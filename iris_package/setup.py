"""
iris-security  -  pip install iris-security
"""
from setuptools import setup, find_packages

with open("README_PKG.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="iris-security",
    version="1.0.0",
    author="Twinkle Kamdar",
    author_email="tkamdar@andrew.cmu.edu",
    description=(
        "Real-time behavioral security monitoring for LLM agent systems. "
        "Detects prompt injection, privilege escalation, data exfiltration, "
        "cross-agent collusion, and behavioral drift."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hell-99/IRIS",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    install_requires=[
        "python-dotenv>=1.0.0",
        "rich>=13.0.0",
        "pydantic>=2.0.0",
    ],
    extras_require={
        # Install with: pip install iris-security[langchain]
        "langchain": [
            "langchain>=0.3.0",
            "langchain-core>=0.3.0",
        ],
        # Install with: pip install iris-security[full]
        "full": [
            "langchain>=0.3.0",
            "langchain-core>=0.3.0",
            "langchain-groq>=0.2.0",
            "langgraph>=0.2.0",
            "fastapi>=0.115.0",
            "uvicorn>=0.32.0",
            "streamlit>=1.40.0",
            "plotly>=5.24.0",
            "pandas>=2.2.0",
            "numpy>=1.26.0",
            "xgboost>=2.1.0",
            "scikit-learn>=1.5.0",
            "groq>=1.0.0",
            "pyyaml>=6.0",
            "httpx>=0.27.0",
        ],
        "dev": [
            "pytest>=8.0.0",
            "black>=24.0.0",
            "ruff>=0.4.0",
            "twine>=5.0.0",
            "build>=1.0.0",
        ],
    },
    keywords=[
        "llm security", "agentic ai", "prompt injection",
        "security monitoring", "langchain", "ai safety",
        "agent security", "behavioral analysis", "iris",
    ],
    project_urls={
        "Bug Reports": "https://github.com/hell-99/IRIS/issues",
        "Source":      "https://github.com/hell-99/IRIS",
    },
)
