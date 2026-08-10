# Agent skills

These skills teach a coding agent how to work with ComfyGuard. ComfyGuard is
read-only: it assesses a ComfyUI instance and writes a report, and never changes
anything itself. The fixing is done by a coding agent, and these skills are how it
knows what to do.

## The skills

- **[comfyguard-audit](comfyguard-audit/SKILL.md)**: run an audit and interpret
  the A-to-F grade. Decide whether an instance is safe to expose and what to do
  next.
- **[comfyguard-remediation](comfyguard-remediation/SKILL.md)**: read a report
  (`report.json` and `FIXES.md`) and fix the findings safely, under the report's
  gates, then verify. This is the core skill.
- **[comfyguard-restore](comfyguard-restore/SKILL.md)**: snapshot before making
  changes, detect drift or tampering with `diff`, and roll back to a known-good
  snapshot if a fix breaks the instance.

## Using them

Each skill is a directory with a `SKILL.md` (a name, a description of when to use
it, and instructions). The format is portable across coding agents.

- **Claude Code**: place a skill directory where Claude Code discovers skills (for
  example under `.claude/skills/`), or point your project at this folder. The
  agent loads a skill when its description matches the task.
- **Other agents**: the `SKILL.md` files are plain Markdown instructions. Load the
  relevant one into the agent's context alongside the report.

The standing baseline the skills build on is [AGENTS.md](../AGENTS.md). The report
and gate contract they depend on is [docs/REPORTING.md](../docs/REPORTING.md).
