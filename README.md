#Property of Alexandre Beaudry, https://github.com/beaudscyber

"""
OWASP Top 10 for LLM Applications (2025 version) - Manual Red Team Prompt Guide (Vulnerabilities 1-10)

A simple interactive helper. Enter the numbers 1-10 and get prompt and/or testing steps for that Vulnerability Class. No automation,
no network calls: it only prints ideas for YOU to manually try against a system you are AUTHORIZED to test.

Usage: python owasp_llm_guide.py
"""
#Each section has a "kind":
#   "prompts" -> copy/paste test prompts
#   "steps" -> testing methodology (for things that are not a single prompt)
#Replace [placeholders] with values relevant to your target
