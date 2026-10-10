"""ContextBridge computer route — policy-controlled files, commands, and processes.

Self-contained, with no runtime dependency on any hosted relay. Every operation
is checked against a local :class:`ComputerPolicy` before it touches the machine.
"""

from .policy import ComputerPolicy, PolicyError, PolicyViolation, load_policy

__all__ = ["ComputerPolicy", "PolicyError", "PolicyViolation", "load_policy"]
