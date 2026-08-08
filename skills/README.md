# Agent skills

These skills teach a coding agent how to work with ComfyHarden. ComfyHarden is
read-only: it assesses a ComfyUI instance and writes a report, and never changes
anything itself. The fixing is done by a coding agent, and these skills are how it
knows what to do.

## The skills

- **[comfyharden-audit](comfyharden-audit/SKILL.md)**: run an audit and interpret
  the A-to-F grade. Decide whether an instance is safe to expose and what to do
  next.
- **[comfyharden-remediation](comfyharden-remediation/SKILL.md)**: read a report
  (`report.json` and `FIXES.md`) and fix the findings safely, under the report's
  gates, then verify. This is the core skill.

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
