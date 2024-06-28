import subprocess
import json
from datetime import datetime, timedelta
import logging
import re

# 设置日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 常量定义
REPO_OWNER = "deepflowio"
REPO_NAME = "deepflow"
CHANGELOG_FILE = "CHANGELOG.md"
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

def get_recent_prs():
    """
    获取最近24小时内的合并PR
    """
    one_day_ago_str = (datetime.utcnow() - timedelta(days=5)).isoformat()
    command = f'gh pr list --repo {REPO_OWNER}/{REPO_NAME} -B main --search "merged:>{one_day_ago_str}" --json number,title,url,author'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"Failed to fetch PRs: {result.stderr}")
        return []
    return json.loads(result.stdout)

def categorize_prs(prs):
    """
    将PR按类型分类
    """
    categorized = {v: [] for v in PR_TYPE_MAPPING.values()}
    for pr in prs:
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
    格式化PR列表为markdown列表
    """
    formatted_prs = []
    for pr in prs:
        author_name = pr['author']['login']
        author_url = f"https://github.com/{author_name}"
        author_link = f"[{author_name}]({author_url})"
        formatted_prs.append(f"* {pr['title']} [#{pr['number']}]({pr['url']}) by {author_link}")
    return formatted_prs

def update_changelog(categorized_prs):
    """
    更新CHANGELOG文件
    """
    with open(CHANGELOG_FILE, 'r', encoding='utf-8') as f:
        content = f.read()

    new_content = content
    for pr_type, prs in categorized_prs.items():
        if not prs:
            continue

        pr_list = format_pr_list(prs)
        pr_list_str = "\n".join(pr_list)

        # 找到或创建对应的类型标题
        pattern = rf"(#### {pr_type}\n)"
        match = re.search(pattern, new_content)
        if match:
            # 在现有标题下追加新的PR条目
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
            # 如果没有找到对应的标题，则添加新的标题和PR条目
            new_section = f"\n\n#### {pr_type}\n{pr_list_str}\n"
            new_content += new_section

    with open(CHANGELOG_FILE, 'w', encoding='utf-8') as f:
        f.write(new_content)

def main():
    logging.info("Fetching recent PRs...")
    prs = get_recent_prs()
    if not prs:
        logging.info("No new PRs found.")
        return

    logging.info(f"Found {len(prs)} PR(s), categorizing...")
    categorized_prs = categorize_prs(prs)

    logging.info("Updating CHANGELOG...")
    update_changelog(categorized_prs)

    logging.info("CHANGELOG updated successfully.")

if __name__ == "__main__":
    main()
