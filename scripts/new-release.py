#!/usr/bin/env python3

"""
Small script to generate the changelog for a new release. It uses information from
both git and Github to create teh changelog in Markdown, which can be simply copy/pasted
to the Github release page.
"""

import datetime
import requests
import subprocess
import os

REPOSITORY  = "hugsy/gef"
TOKEN       = os.getenv("GITHUB_REPO_TOKEN")
DEBUG       = False
OUTPUT_FILE = "/tmp/CHANGELOG.md"


def dbg(x: str):
    if DEBUG:
        print(x)

def shell(x: str):
    dbg(f"   executing: {x}")
    return subprocess.check_output(x, shell=True).strip().decode("utf8")


version = datetime.date.today().strftime("%Y.%m")
codename = shell("random-word").title()
latest_tag = shell("git describe --abbrev=0")

with open(OUTPUT_FILE, "w") as f:
    print(f"Creating changelog for {version} in {OUTPUT_FILE}")
    f.write(f"# Changelog: {version} - {codename}{os.linesep}{os.linesep}")

    dbg(f"Adding commit summary...")
    f.write(f"## Highlights of `{codename}`{os.linesep}{os.linesep}")
    f.write(f"{os.linesep}{os.linesep}")

    dbg(f"Adding contributor summary...")
    f.write(f"## Contributors{os.linesep}{os.linesep}")
    contributors = shell(f"git log {latest_tag}... --pretty=format:'%aN' | sort -u").splitlines()
    total_commits = 0
    f.write(f"| Name | Number of commits | {os.linesep}")
    f.write(f"|--|--| {os.linesep}")
    for contrib in contributors:
        commits = shell(f'git log {latest_tag}...  --pretty=format:"%h" --author="{contrib}"').splitlines()
        nb_commits = len(commits)
        f.write(f"| {contrib} | {nb_commits} |{os.linesep}")
        total_commits += int(nb_commits)
    f.write("{os.linesep}{os.linesep}")

    dbg("Adding Github info...")
    h = requests.get(f"https://api.github.com/repos/${REPOSITORY}/issues?state=closed&milestone.title=Release+{version}",
                     headers={"Authorization": f"token {TOKEN}"})

    js = h.json()
    prs = { x['number']: x['html_url'] for x in js if "pull" in x['html_url'] }
    issues = { x['number']: x['html_url'] for x in js if "issues" in x['html_url'] }

    f.write(f"## Closed Issues{os.linesep}{os.linesep}")
    f.write(f" * {len(issues)} issues closed (")
    for nb in issues:
        url = issues[nb]
        f.write(f" [{nb}]({url}) &bull; ")
    f.write(f"){os.linesep}")

    f.write(f"{os.linesep}{os.linesep}")

    f.write(f"## Closed Pull Requests{os.linesep}{os.linesep}")
    f.write(f" * {len(prs)} PRs closed (")
    for nb in prs:
        url = prs[nb]
        f.write(f" [{nb}]({url}) &bull; ")
    f.write("){os.linesep}")

    f.write("{os.linesep}{os.linesep}")

    dbg(f"Adding commit summary...")
    f.write(f"## Commit details{os.linesep}{os.linesep}")
    f.write(f"<details><summary>")
    f.write(f"{total_commits} commits since <b>{latest_tag}</b>")
    f.write(f"</summary>{os.linesep}{os.linesep}")
    f.write( shell(f"""git log "{latest_tag}"...HEAD  --pretty=format:' * %cs [%h](http://github.com/hugsy/gef/commit/%H) &bull; *%aN* &bull; %s ' --reverse""") )
    f.write(f"{os.linesep}")
    f.write( shell(f"""git diff --no-color --stat {latest_tag} HEAD""") )
    f.write(f"{os.linesep}")
    f.write(f"</details>")

    f.write(f"{os.linesep}{os.linesep}")

    print(f"Done, the changelog file was written to `{OUTPUT_FILE}`")


print(f"Push new release {version} ({codename}) live? [y/N] ")
if input().lower().startswith("y"):
    shell(f"""git tag --annotate "{version}" --message "Release {version} - {codename}" --sign""")
    shell(f"""git push origin "{version}" """)

