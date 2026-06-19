# Contributing to Android APK Malware Analyzer

Thank you for your interest in contributing to the Android APK Malware Analyzer! We welcome contributions to improve features, code quality, model accuracy, and user experience.

## How to Contribute

1. **Fork the Repository**: Create a personal copy of the project on GitHub.
2. **Clone the Repository**: Clone your fork to your local machine:
   ```bash
   git clone https://github.com/YOUR_USERNAME/IIT_HD_PROJECT.git
   ```
3. **Set Up the Environment**:
   - Create a virtual environment:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate  # On Windows, use .venv\Scripts\activate
     ```
   - Install dependencies:
     ```bash
     pip install -r requirements.txt
     ```
4. **Create a Feature Branch**: Use a descriptive branch name for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```
5. **Implement Changes**:
   - Follow PEP 8 style guide for Python code.
   - Keep logic modular and document new functions/classes.
6. **Run Verification**:
   - Run the streamlit dashboard locally to ensure no UI breakages:
     ```bash
     streamlit run dashboard.py
     ```
   - Check CLI tool outputs:
     ```bash
     python apk_analyzer.py
     ```
7. **Commit & Push**: Commit your changes with clear messages and push them to your fork.
8. **Create a Pull Request**: Submit a Pull Request (PR) to the `main` branch of this repository.

## Feedback and Issues

If you find a bug, security vulnerability, or have a feature suggestion, please open an Issue in the GitHub repository. Provide as much context as possible (e.g., sample manifests, log outputs).
