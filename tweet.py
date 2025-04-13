import requests
import tweepy
from urllib.parse import quote
import os
import re

# ==== Twitter API credentials from environment variables ====
API_KEY = os.getenv("TWITTER_API_KEY")
API_SECRET = os.getenv("TWITTER_API_SECRET")
ACCESS_TOKEN = os.getenv("TWITTER_ACCESS_TOKEN")
ACCESS_TOKEN_SECRET = os.getenv("TWITTER_ACCESS_TOKEN_SECRET")

# ==== GitHub repo details ====
OWNER = "projectdiscovery"
REPO = "nuclei-templates"

# ==== Fetch latest commits from the last hour ====
commits_url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits?since=2025-04-14T00:00:00Z"
commits = requests.get(commits_url).json()

# Track added templates
cve_templates = []
non_cve_templates = []

# ==== Categorize templates into CVE and Non-CVE ====
for commit in commits:
    sha = commit["sha"]
    commit_detail_url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits/{sha}"
    commit_detail = requests.get(commit_detail_url).json()

    for file in commit_detail.get("files", []):
        if file["filename"].endswith(".yaml") and file["status"] == "added":
            template_name = file["filename"].split("/")[-1].replace(".yaml", "")
            if "CVE" in template_name:
                cve_templates.append(template_name)
            else:
                non_cve_templates.append(template_name)

# ==== Avoid Duplicate Posts ====
last_tweeted_file = "last_tweeted.txt"
last_tweeted = []

if os.path.exists(last_tweeted_file):
    with open(last_tweeted_file, "r") as f:
        last_tweeted = f.read().strip().split("\n")

# ==== Extract CVE Number from Template Name ====
def extract_cve_number(template_name):
    # Look for a pattern like CVE-YYYY-NNNNN
    match = re.search(r"CVE-\d{4}-\d{4,7}", template_name)
    return match.group(0) if match else "No CVE"

# ==== Post CVE Templates ====
if cve_templates:
    latest_cve = cve_templates[-1]  # Most recent CVE template
    if latest_cve not in last_tweeted:
        cve_number = extract_cve_number(latest_cve)  # Extract CVE number
        # Generate GitHub file URL
        raw_url = f"https://github.com/{OWNER}/{REPO}/blob/main/{quote(latest_cve)}"
        short_url = requests.get(f"http://tinyurl.com/api-create.php?url={raw_url}").text

        # Create tweet for CVE Template
        tweet = f"🚨 New CVE Template Alert! 🚨\n\n🔥 {latest_cve} ({cve_number}) 🔥\n🔗 {short_url}\n\n#bugbountytips #CyberSecurity #InfoSec #BugBounty #Nuclei #RedTeam #ThreatHunting #Vulnerability #CVE"
        tweet = tweet[:250]  # Ensure tweet is <= 250 characters

        # Post the tweet
        try:
            client = tweepy.Client(
                consumer_key=API_KEY,
                consumer_secret=API_SECRET,
                access_token=ACCESS_TOKEN,
                access_token_secret=ACCESS_TOKEN_SECRET
            )
            client.create_tweet(text=tweet)
            print("✅ CVE Tweet posted successfully!")
            last_tweeted.append(latest_cve)
        except Exception as e:
            print(f"❌ Error while posting CVE tweet: {str(e)}")

# ==== Post Non-CVE Templates ====
if non_cve_templates:
    latest_non_cve = non_cve_templates[-1]  # Most recent Non-CVE template
    if latest_non_cve not in last_tweeted:
        # Generate GitHub file URL
        raw_url = f"https://github.com/{OWNER}/{REPO}/blob/main/{quote(latest_non_cve)}"
        short_url = requests.get(f"http://tinyurl.com/api-create.php?url={raw_url}").text

        # Create tweet for Non-CVE Template
        tweet = f"🚨 New Nuclei Template Alert! 🚨\n\n🔥 {latest_non_cve} 🔥\n🔗 {short_url}\n\n#CyberSecurity #BugBounty #Nuclei #InfoSec #Vulnerability #Exploit #RedTeam #Pentest #WebSecurity"
        tweet = tweet[:250]  # Ensure tweet is <= 250 characters

        # Post the tweet
        try:
            client = tweepy.Client(
                consumer_key=API_KEY,
                consumer_secret=API_SECRET,
                access_token=ACCESS_TOKEN,
                access_token_secret=ACCESS_TOKEN_SECRET
            )
            client.create_tweet(text=tweet)
            print("✅ Non-CVE Tweet posted successfully!")
            last_tweeted.append(latest_non_cve)
        except Exception as e:
            print(f"❌ Error while posting Non-CVE tweet: {str(e)}")

# Save the latest tweeted templates to avoid duplication
with open(last_tweeted_file, "w") as f:
    f.write("\n".join(last_tweeted))
