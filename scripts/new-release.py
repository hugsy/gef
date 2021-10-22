#!/usr/bin/env python3

"""
Small script to generate the changelog for a new release. It uses information from
both git and Github to create teh changelog in Markdown, which can be simply copy/pasted
to the Github release page.

The script requires a Github token to be set in the environment variable `GITHUB_REPO_TOKEN`.
As the name implies, only scope `repo` is required for the token (which can be generated
from https://github.com/settings/tokens/new).
"""

import argparse
import datetime
import requests
import subprocess
import os
import pathlib
import tempfile

__author__    =   "@_hugsy_"
__version__   =   0.1
__licence__   =   "MIT"
__file__      =   "new-release.py"
__desc__      =   "Generate a new release for a Github project."
__usage__     =   f"""{__file__} v{__version__}\nby {__author__} under {__licence__}\nsyntax: {__file__} [options] args"""


REPOSITORY     = "hugsy/gef"
GITHUB_TOKEN   = os.getenv("GITHUB_REPO_TOKEN")
DEBUG          = False
OUTPUT_FILE    = pathlib.Path( tempfile.gettempdir() ) / "CHANGELOG.md"


def dbg(x: str):
    if DEBUG:
        print(x)
    return


def shell(x: str) -> str:
    dbg(f"   executing: {x}")
    return subprocess.check_output(x, shell=True).strip().decode("utf8")


def generate_changelog(args: argparse.Namespace) -> bool:
    """Generate the changelog for the new release."""
    latest_tag = shell("git describe --abbrev=0")

    print(f"Creating changelog for {args.version} in {args.output_file.name}")
    args.output_file.write(f"# Changelog: {args.version} - {args.codename}{os.linesep}{os.linesep}")

    dbg("Adding commit summary...")
    args.output_file.write(f"## Highlights of `{args.codename}`{os.linesep}{os.linesep}")
    args.output_file.write(f"{os.linesep}{os.linesep}")

    dbg("Adding contributor summary...")
    args.output_file.write(f"## Contributors{os.linesep}{os.linesep}")
    contributor_names = shell(f"git log {latest_tag}..HEAD --pretty=format:'%aN' | sort -u").splitlines()
    commits = {}
    for author in contributor_names:
        author_commits = shell(f'git log {latest_tag}..HEAD  --pretty=format:"%h" --author="{author}"').splitlines()
        commits[ author ] = len(author_commits)
    total_commits = sum(commits.values())

    args.output_file.write(f"| Author | Number of commits | {os.linesep}")
    args.output_file.write(f"|:--|--:| {os.linesep}")
    commits_sorted = dict(sorted(commits.items(), key=lambda item: -item[1]))
    for author in commits_sorted:
        args.output_file.write(f"| {author} | {commits[author]}|{os.linesep}")
    args.output_file.write(f"{os.linesep}{os.linesep}")

    dbg("Adding Github info...")
    url = f"https://api.github.com/repos/{args.repository}/issues?state=closed&milestone.title=Release%3a%20{args.version}"
    js = requests.get(url, headers={"Authorization": f"token {args.token}"}).json()
    prs = { x['number']: x['html_url'] for x in js if "pull" in x['html_url'] }
    issues = { x['number']: x['html_url'] for x in js if "issues" in x['html_url'] }
    closed_prs_item = " &bull; ".join([f" [{nb}]({url}) " for nb, url in prs.items()])
    closed_issues_item = " &bull; ".join([f" [{nb}]({url}) " for nb, url in issues.items()])
    args.output_file.write(f"""
## Closed Issues

  * {len(issues)} issues closed ({closed_issues_item})


## Closed Pull Requests

 * {len(prs)} PRs closed ({closed_prs_item})

""")

    dbg("Adding commit summary...")
    log = shell(f"""git log {latest_tag}..HEAD  --pretty=format:' * %cs [%h](https://github.com/{args.repository}/commit/%H) &bull; *%aN* &bull; %s ' --reverse""")
    diff = shell(f"""git diff --no-color --stat {latest_tag}..HEAD""")
    args.output_file.write(f"""
## Commit details

<details>
<summary>
{total_commits} commits since <b>{latest_tag}</b>
</summary>

### Commit log

{log}

### File diff

```diff
{diff}
```

</details>

""")
    print(f"Done, the changelog file was written to `{args.output_file.name}`")

    if args.push_release:
        shell(f"""git tag --annotate "{args.version}" --message "Release {args.version} - {args.codename}" --sign""")
        shell(f"""git push origin "{args.version}" """)

    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage = __usage__, description = __desc__, prog = __file__)
    parser.add_argument("--debug", action="store_true", default=DEBUG,
                        help="Enable debug output")
    parser.add_argument("-r", "--repository", type=str, default=REPOSITORY,
                        help="Specify the repository (default: '%(default)s')")
    parser.add_argument("-t", "--token", dest="token", type=str, metavar="TOKEN",
                        default=GITHUB_TOKEN, help="Specify the Github token to use (requires `repo` scope)")
    parser.add_argument("-o", "--output-file", type=argparse.FileType('w', encoding='UTF-8'), default=open(str(OUTPUT_FILE.absolute()), 'w'),
                        metavar="/path/to/output_file.md", help=f"Specify the output file (default: '{OUTPUT_FILE}')")
    parser.add_argument("--version", type=str, default=datetime.date.today().strftime("%Y.%m"),
                        help="Specify the version number (default: '%(default)s')")
    parser.add_argument("--codename", type=str, default=shell("random-word").title(),
                        help="Specify the version codename (default: '%(default)s')")
    parser.add_argument("--push-release", action="store_true", default=False,
                        help="Create the new tag and publish the release on Github")

    x = parser.parse_args()
    DEBUG = x.debug
    generate_changelog(x)
    exit(0)
