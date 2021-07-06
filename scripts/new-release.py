#!/usr/bin/env python3

import datetime
import requests
import subprocess
import os

DEBUG = False

def dbg(x):
    if DEBUG:
        print(f"{x}")

def shell(x):
    dbg(f"   executing: {x}")
    return subprocess.check_output(x, shell=True).strip().decode("utf8")


version = datetime.date.today().strftime("%Y.%m")
codename = shell("random-word").title()
latest_tag = shell("git describe --abbrev=0")

fname = "/tmp/CHANGELOG.md"
with open(fname, "w") as f:
    print(f"Creating changelog for {version} in {fname}")
    f.write(f"# Changelog: {version} - {codename}\n\n")

    dbg(f"Adding commit summary...")
    f.write(f"## Highlights of `{codename}`\n\n")
    f.write("\n\n")

    dbg(f"Adding contributor summary...")
    f.write("## Contributors\n\n")
    contributors = shell(f"git log {latest_tag}... --pretty=format:'%aN' | sort -u").splitlines()
    total_commits = 0
    f.write("| Name | Number of commits | \n")
    f.write("|--|--| \n")
    for contrib in contributors:
        commits = shell(f'git log {latest_tag}...  --pretty=format:"%h" --author="{contrib}"').splitlines()
        nb_commits = len(commits)
        f.write(f"| {contrib} | {nb_commits} |\n")
        total_commits += int(nb_commits)
    f.write("\n\n")

    dbg("Adding Github info...")
    h = requests.get(f"https://api.github.com/repos/hugsy/gef/issues?state=closed&milestone.title=Release+{version}",
                     headers={"Authorization": f"token {os.getenv('GITHUB_REPO_TOKEN')}"})

    js = h.json()
    prs = { x['number']: x['html_url'] for x in js if "pull" in x['html_url'] }
    issues = { x['number']: x['html_url'] for x in js if "issues" in x['html_url'] }

    f.write(f"## Closed Issues\n\n")
    f.write(f" * {len(issues)} issues closed (")
    for nb in issues:
        url = issues[nb]
        f.write(f" [{nb}]({url}) &bull; ")
    f.write(")\n")

    f.write("\n\n")

    f.write(f"## Closed Pull Requests\n\n")
    f.write(f" * {len(prs)} PRs closed (")
    for nb in prs:
        url = prs[nb]
        f.write(f" [{nb}]({url}) &bull; ")
    f.write(")\n")

    f.write("\n\n")

    dbg(f"Adding commit summary...")
    f.write(f"## Commit details\n\n")
    f.write(f"<details><summary>{total_commits} commits since <b>{latest_tag}</b></summary>\n\n")
    f.write( shell(f"""git log "{latest_tag}"...HEAD  --pretty=format:' * %cs [%h](http://github.com/hugsy/gef/commit/%H) &bull; *%aN* &bull; %s ' --reverse""") )
    f.write("\n")
    f.write(f"</details>")

    f.write("\n\n")

    print(f"Done, result in `{fname}`")


print(f"Push new release {version} ({codename}) live? [y/N] ")
if input().lower().startswith("y"):
    shell(f"""git tag --annotate "{version}" --message "Release {version} - {codename}" --sign""")
    shell(f"""git push origin "{version}" """)

