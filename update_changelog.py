import subprocess
import json
from datetime import datetime, timedelta
import logging
import re
import argparse
import os

# Set logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
REPO_OWNER = "deepflowio"
REPO_NAME = "deepflow"
PR_TYPE_MAPPING = {
    "fix": "Bug Fix",
    "feat": "NEW FEATURE",
    "docs": "Documentation",
    "style": "Code Style",
    "refactor": "Refactoring",
    "perf": "Performance",
    "test": "Testing",
    "chore": "Chore",
    "other": "OTHER"
}

def get_recent_prs(branch):
    """
    Get PRs merged in the last 24 hours from the specified branch
    """
    one_day_ago_str = (datetime.utcnow() - timedelta(days=1)).isoformat()
    command = f'gh pr list --repo {REPO_OWNER}/{REPO_NAME} -B {branch} --search "merged:>{one_day_ago_str}" --json number,title,url,author'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"Failed to fetch PRs: {result.stderr}")
        return []
    return json.loads(result.stdout)

def categorize_prs(prs):
    """
    Categorize PRs by type, excluding 'Update changelog for xx' PRs
    """
    categorized = {v: [] for v in PR_TYPE_MAPPING.values()}
    for pr in prs:
        if "update changelog for" in pr['title'].lower():
            continue  # Exclude 'Update changelog for xx' PRs

        matched = False
        for key, value in PR_TYPE_MAPPING.items():
            if key in pr['title'].lower():
                categorized[value].append(pr)
                matched = True
                break
        if not matched:
            categorized[PR_TYPE_MAPPING['other']].append(pr)
    return categorized

def format_pr_list(prs):
    """
    Format PR list as markdown list
    """
    formatted_prs = []
    for pr in prs:
        author_name = pr['author']['login']
        author_url = f"https://github.com/{author_name}"
        author_link = f"[{author_name}]({author_url})"
        formatted_prs.append(f"* {pr['title']} [#{pr['number']}]({pr['url']}) by {author_link}")
    return formatted_prs

def update_changelog(changelog_file, categorized_prs, branch):
    """
    Update the CHANGELOG file
    """
    if not os.path.exists(changelog_file):
        logging.info(f"{changelog_file} does not exist. Creating a new file.")
        with open(changelog_file, 'w', encoding='utf-8') as f:
            f.write(f"### Table of Contents\n\n**[DeepFlow release {branch}](#{branch})**<br/>\n\n# Changelog\n\n### <a id=\"{branch}\"></a>DeepFlow release {branch}\n\n#### New Feature\n\n#### Bug Fix\n\n")

    with open(changelog_file, 'r', encoding='utf-8') as f:
        content = f.read()

    new_content = content
    for pr_type, prs in categorized_prs.items():
        if not prs:
            continue

        pr_list = format_pr_list(prs)
        pr_list_str = "\n".join(pr_list)

        # Find or create the corresponding type title
        pattern = rf"(#### {pr_type}\n)"
        match = re.search(pattern, new_content)
        if match:
            # Append new PR entries under the existing title
            start_idx = match.end()
            end_idx = new_content.find('\n#### ', start_idx)
            if end_idx == -1:
                end_idx = len(new_content)
            section = new_content[start_idx:end_idx].strip()
            if section:
                existing_prs = section.split('\n')
                new_prs = [pr for pr in pr_list if pr not in existing_prs]
                pr_list_str = "\n".join(new_prs) + "\n" + section
            new_content = new_content[:start_idx] + pr_list_str + "\n" + new_content[end_idx:]
        else:
            # If the title is not found, add a new title and PR entries
            new_section = f"\n\n#### {pr_type}\n{pr_list_str}\n"
            new_content += new_section

    with open(changelog_file, 'w', encoding='utf-8') as f:
        f.write(new_content)

def main(branch, changelog_file):
    logging.info("Fetching recent PRs...")
    prs = get_recent_prs(branch)
    if not prs:
        logging.info("No new PRs found.")
        return

    logging.info(f"Found {len(prs)} PR(s), categorizing...")
    categorized_prs = categorize_prs(prs)

    logging.info("Updating CHANGELOG...")
    update_changelog(changelog_file, categorized_prs, branch)

    logging.info("CHANGELOG updated successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Update changelog with recent PRs.")
    parser.add_argument("-B", "--branch", required=True, help="Branch name to fetch PRs from.")
    parser.add_argument("changelog_file", help="Path to the changelog file.")
    args = parser.parse_args()
    main(args.branch, args.changelog_file)
