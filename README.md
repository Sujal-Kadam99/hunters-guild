# Hunters Guild

Hunters Guild is an AI-driven security audit tool. 

## Known Defects
- **Python Sandbox**: Currently implemented as a Stub or known defect. It uses standard `subprocess` execution without proper Windows isolation/containerization, which is insecure against malicious code execution on Windows hosts.
