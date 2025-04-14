import requests
import tweepy
import os
from datetime import datetime, timedelta
from urllib.parse import quote

# ==== Twitter API credentials ====
API_KEY = os.getenv("TWITTER_API_KEY")
API_SECRET = os.getenv("TWITTER_API_SECRET")
ACCESS_TOKEN = os.getenv("TWITTER_ACCESS_TOKEN")
ACCESS_TOKEN_SECRET = os.getenv("TWITTER_ACCESS_TOKEN_SECRET")

OWNER = "projectdiscovery"
REPO = "nuclei-templates"
TWEET_LOG_FILE = "last_tweeted1.txt"

# ==== First-time init ====
if not os.path.exists("initialized.txt"):
    open(TWEET_LOG_FILE, "w").close()
    with open("initialized.txt", "w") as f:
        f.write("initialized")

# ==== Load already tweeted templates ====
if os.path.exists(TWEET_LOG_FILE):
    with open(TWEET_LOG_FILE, "r") as f:
        tweeted = set(line.strip() for line in f.readlines())
else:
    tweeted = set()

# ==== Fetch recent commits ====
cutoff_time = datetime.utcnow() - timedelta(hours=1)
commits_url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits"
commits = requests.get(commits_url).json()

latest_template = None
latest_time = None

for commit in commits:
    commit_time = datetime.strptime(commit["commit"]["author"]["date"], "%Y-%m-%dT%H:%M:%SZ")
    if commit_time < cutoff_time:
        continue

    sha = commit["sha"]
    detail_url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits/{sha}"
    detail = requests.get(detail_url).json()

    for file in detail.get("files", []):
        if file["status"] != "added" or not file["filename"].endswith(".yaml"):
            continue

        path = file["filename"]
        if path in tweeted:
            continue

        if not latest_time or commit_time > latest_time:
            latest_template = (commit_time, path)
            latest_time = commit_time

# ==== Prepare and tweet ====
def create_tweet(vuln_name, path, is_cve):
    short_url = requests.get(f"http://tinyurl.com/api-create.php?url=https://github.com/{OWNER}/{REPO}/blob/main/{quote(path)}").text
    prefix = "🚨 New CVE Template!" if is_cve else "🚨 New Nuclei Template!"
    tags = "#bugbountytips #CyberSecurity #InfoSec #BugBounty #Nuclei #RedTeam #CTF #Hacking"
    tweet = f"{prefix}\n🔥 {vuln_name}\n🔗 {short_url}\n{tags}"
    if len(tweet) > 250:
        tweet = f"{prefix}\n{vuln_name}\n{short_url}\n{tags}"
    if len(tweet) > 250:
        tweet = f"{vuln_name}\n{short_url}\n{tags}"
    if len(tweet) > 250:
        tweet = f"{vuln_name}\n{short_url}"
    return tweet[:250]

def post_tweet(tweet):
    try:
        client = tweepy.Client(
            consumer_key=API_KEY,
            consumer_secret=API_SECRET,
            access_token=ACCESS_TOKEN,
            access_token_secret=ACCESS_TOKEN_SECRET
        )
        client.create_tweet(text=tweet)
        print("✅ Tweeted:\n", tweet)
    except Exception as e:
        print("❌ Failed to tweet:", e)

if latest_template:
    _, path = latest_template
    raw_url = f"https://raw.githubusercontent.com/{OWNER}/{REPO}/main/{path}"
    yaml_content = requests.get(raw_url).text
    name_line = next((line for line in yaml_content.splitlines() if line.startswith("name:")), None)
    vuln_name = name_line.split(":", 1)[1].strip() if name_line else path.split("/")[-1]
    is_cve = "CVE-" in vuln_name

    tweet = create_tweet(vuln_name, path, is_cve)
    post_tweet(tweet)

    with open(TWEET_LOG_FILE, "a") as f:
        f.write(f"{path}\n")
