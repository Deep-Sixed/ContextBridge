"""ContextBridge computer route — policy-controlled files, commands, and processes.

Self-contained replacement for the Desktop Commander tool surface: no runtime
dependency on Desktop Commander or any hosted relay. Every operation is checked
against a local :class:`ComputerPolicy` before it touches the machine.
"""

from .policy import ComputerPolicy, PolicyError, PolicyViolation, load_policy

__all__ = ["ComputerPolicy", "PolicyError", "PolicyViolation", "load_policy"]
