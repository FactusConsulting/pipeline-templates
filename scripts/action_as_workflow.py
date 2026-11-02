#!/usr/bin/env python3
"""Wrap a composite action's steps in a throwaway workflow so actionlint can check them.

actionlint only understands workflow files; this turns `runs.steps` of an action.yml into a
reusable-workflow job (inputs become workflow_call inputs) and writes it to stdout.
Needs PyYAML (present on GitHub-hosted runners; `pip install pyyaml` elsewhere).
"""

import sys

import yaml


def main(path):
    with open(path, encoding="utf-8") as handle:
        action = yaml.safe_load(handle)
    inputs = {name: {"type": "string", "required": False, "description": spec.get("description", name)}
              for name, spec in (action.get("inputs") or {}).items()}
    steps = []
    for step in action["runs"]["steps"]:
        step = dict(step)
        step.pop("shell", None)  # composite steps need `shell`; in a workflow the default (bash) applies
        steps.append(step)
    workflow = {
        "on": {"workflow_call": {"inputs": inputs}},
        "jobs": {"composite": {"runs-on": "ubuntu-latest", "steps": steps}},
    }
    sys.stdout.write(yaml.safe_dump(workflow, sort_keys=False, width=1000))


if __name__ == "__main__":
    main(sys.argv[1])
