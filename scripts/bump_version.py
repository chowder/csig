#!/usr/bin/env python3
import os
import re
import sys


def bump_version(current: str, bump_type: str) -> str:
    major, minor, patch = map(int, current.split('.'))
    if bump_type == 'major':
        return f"{major + 1}.0.0"
    elif bump_type == 'minor':
        return f"{major}.{minor + 1}.0"
    elif bump_type == 'patch':
        return f"{major}.{minor}.{patch + 1}"
    else:
        raise ValueError(f"Invalid bump type: {bump_type}")


def main():
    if len(sys.argv) != 2:
        print("Usage: bump_version.py <major|minor|patch>", file=sys.stderr)
        sys.exit(1)

    bump_type = sys.argv[1]

    with open('pyproject.toml', 'r') as f:
        content = f.read()
        match = re.search(r'^version = "([^"]+)"', content, re.MULTILINE)
        if not match:
            print("Error: Could not find version in pyproject.toml", file=sys.stderr)
            sys.exit(1)
        current_version = match.group(1)

    new_version = bump_version(current_version, bump_type)

    # Update pyproject.toml
    new_content = re.sub(
        r'^version = "[^"]+"',
        f'version = "{new_version}"',
        content,
        count=1,
        flags=re.MULTILINE
    )
    with open('pyproject.toml', 'w') as f:
        f.write(new_content)

    # Update csig/__init__.py
    with open('csig/__init__.py', 'r') as f:
        init_content = f.read()
    new_init = re.sub(
        r'__version__ = "[^"]+"',
        f'__version__ = "{new_version}"',
        init_content
    )
    with open('csig/__init__.py', 'w') as f:
        f.write(new_init)

    # Output for GitHub Actions
    github_output = os.environ.get('GITHUB_OUTPUT')
    if github_output:
        with open(github_output, 'a') as f:
            f.write(f"current_version={current_version}\n")
            f.write(f"new_version={new_version}\n")
    else:
        # Local usage: print to stdout
        print(f"Bumped version: {current_version} -> {new_version}")


if __name__ == '__main__':
    main()
