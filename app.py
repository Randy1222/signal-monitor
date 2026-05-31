import cv2
import openai
import requests
import os
import time
import csv
import smtplib
import threading
import feedparser
import base64
import webbrowser
import pandas as pd
from datetime import datetime
from email.mime.text import MIMEText
import streamlit as st
from apify_client import ApifyClient
from openai import OpenAI

# --- GLOBAL CONFIGURATION & APP INITIALIZATION ---
st.set_page_config(page_title="Global Threat & Crisis Monitor", page_icon="🚨", layout="wide")

CSV_FILE = "haiti_negative_content.csv"
KEYWORDS = ["gang", "violence", "clash", "killed", "dead", "protest", "armed", 
            "kidnap", "insecurity", "shooting", "gunmen", "Port-au-Prince"]

RSS_FEEDS = [
    "https://www.haitilibre.com/en/rss.xml",
    "https://haitiantimes.com/feed/",
    "https://haitiliberte.com/feed/",
    "https://lenouvelliste.com/feed",
    "https://rezo.net/feed",
    "https://juno7.ht/feed/",
    "https://globalvoices.org/-/world/caribbean/haiti/feed/",
]

# Ensure tracking storage layers exist natively
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(["timestamp", "source", "title", "link", "violence", "graphic", "type"])

# --- SIDEBAR COMPONENT (SECURE RECEPTACLE) ---
st.sidebar.header("🔑 Engine Credentials")
openai_key_input = st.sidebar.text_input("OpenAI API Key", type="password", help="Input sk-proj-... credential layer")
apify_token_input = st.sidebar.text_input("Apify API Token", type="password", help="Input apify_api_... credential layer")

st.sidebar.header("⚙️ Live Feed Controls")
search_query = st.sidebar.text_input("TikTok Query Modifer", value="Haiti crisis")
max_results = st.sidebar.slider("TikTok Buffer Depth", min_value=1, max_value=10, value=3)

st.sidebar.header("✉️ Automated SMTP Dispatches")
enable_email = st.sidebar.checkbox("Activate Email Warning Relays", value=False)
sender_mail = st.sidebar.text_input("Sender Address (Gmail)", value="your_email@gmail.com")
sender_pass = st.sidebar.text_input("App Password", type="password")
receiver_mail = st.sidebar.text_input("Target Address", value="your_email@gmail.com")

# --- CORE LOGIC LAYER FUNCTIONS ---
def load_processed_links():
    processed = set()
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if len(row) > 3: 
                    processed.add(row[3])
    return processed

def send_email_alert(title, source, link, violence, graphic):
    if not enable_email or not sender_pass: 
        return
    try:
        subject = f"🚨 Threat Intelligence Alert - {source}"
        body = f"Source Category: {source}\nTitle/Context: {title}\nResource Target: {link}\nViolence Matrix: {violence:.4f}\nGraphic Index: {graphic:.4f}"
        msg = MIMEText(body.strip())
        msg['Subject'] = subject
        msg['From'] = sender_mail
        msg['To'] = receiver_mail
        
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_mail, sender_pass)
            server.sendmail(sender_mail, [receiver_mail], msg.as_string())
    except Exception as e:
        print(f"SMTP dispatch failure event: {e}")

def encode_image_to_base64(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

def fetch_tiktoks(token, query, limit):
    apify_client = ApifyClient(token)
    run_input = {"searchQueries": [query], "resultsPerPage": limit, "shouldDownloadVideos": True}
    try:
        run = apify_client.actor("clockworks/tiktok-scraper").call(run_input=run_input)
        video_records = []
        for item in apify_client.dataset(run.default_dataset_id).iterate_items():
            download_url = item.get("videoUrl") or item.get("video", {}).get("downloadAddr") or item.get("video", {}).get("playAddr")
            video_url = item.get("webVideoUrl") or item.get("shareUrl")
            description = item.get("text") or item.get("desc") or "No description available"
            video_records.append({"url": video_url, "download_url": download_url, "desc": description})
        return video_records
    except Exception as e:
        st.error(f"Apify Engine Instance Failure: {e}")
        return []

def analyze_video_frames(video_path, description, ai_client, status_box, original_url):
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened(): 
        return
    fps = cap.get(cv2.CAP_PROP_FPS)
    interval = int(2 * fps) if fps > 0 else 30
    frame_count = 0
    
    while True:
        success, frame = cap.read()
        if not success: 
            break
        if frame_count % interval == 0:
            temp_path = f"temp_frame_{os.getpid()}_{frame_count}.jpg"
            cv2.imwrite(temp_path, frame)
            try:
                b64_str = encode_image_to_base64(temp_path)
                status_box.text(f"🧠 Computer Vision matrix inspecting sequence array block: {frame_count}...")
                
                res = ai_client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{
                        "role": "user",
                        "content": [
                            {"type": "text", "text": f"Analyze this image frame from video item containing description: '{description}'. Does the content display active weapon brandishing, direct tactical friction, structural devastation or active riot environments? Reply with strictly one target word response: 'FLAGGED' or 'SAFE'."},
                            {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64_str}"}}
                        ]
                    }],
                    max_tokens=10
                )
                judgment = res.choices[0].message.content.strip().upper()
                if "FLAGGED" in judgment:
                    send_email_alert(description, "TikTok Stream Analysis", original_url, 1.0, 1.0)
                    with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
                        csv.writer(f).writerow([datetime.now().isoformat(), "TikTok Stream", description, original_url, 1.0, 1.0, "Video Stream Frame Match"])
                    cap.release()
                    if os.path.exists(temp_path): os.remove(temp_path)
                    return True, frame_count
            except:
                pass
            finally:
                if os.path.exists(temp_path): os.remove(temp_path)
        frame_count += 1
    cap.release()
    return False, None

def check_rss_feeds_background():
    """Background loop analyzing textual data matrices."""
    if not openai_key_input or openai_key_input == "":
        return
    local_client = OpenAI(api_key=openai_key_input)
    processed_links = load_processed_links()
    
    for url in RSS_FEEDS:
        try:
            feed = feedparser.parse(url)
            feed_title = getattr(feed.feed, 'title', 'External News Source')
            for entry in feed.entries[:8]:
                link = getattr(entry, 'link', None)
                if not link or link in processed_links: 
                    continue
                
                combined_text = f"{getattr(entry, 'title', '')} {entry.get('summary', '')}".lower()
                if any(kw in combined_text for kw in KEYWORDS):
                    try:
                        response = local_client.moderations.create(
                            model="omni-moderation-latest",
                            input=[{"type": "text", "text": f"Source: {feed_title}. Context: {entry.title} {entry.get('summary', '')}"}]
                        )
                        res_obj = response.results[0]
                        v_score = getattr(res_obj.category_scores, "violence", 0.0)
                        g_score = getattr(res_obj.category_scores, "violence/graphic", 0.0)
                        
                        if res_obj.flagged or g_score > 0.55 or v_score > 0.65:
                            send_email_alert(entry.title, feed_title, link, v_score, g_score)
                            with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
                                csv.writer(f).writerow([datetime.now().isoformat(), feed_title, entry.title, link, round(v_score, 4), round(g_score, 4), "RSS Content Sync"])
                    except:
                        pass
                processed_links.add(link)
        except:
            continue

# --- BACKGROUND MONITOR MULTI-THREAD ENGINE TRIGGER ---
if "bg_loop_active" not in st.session_state and openai_key_input:
    st.session_state["bg_loop_active"] = True
    threading.Thread(target=check_rss_feeds_background, daemon=True).start()

# --- MAIN DASHBOARD INTERFACE UI ---
st.title("🚨 Global Threat & Crisis Intel Dashboard")
st.markdown("Real-time automated content moderation analysis parsing active international streams.")

# Execution Trigger Buttons for Video Extraction pipelines
if st.button("🚀 Execute Video Stream Verification", type="primary"):
    if not openai_key_input or not apify_token_input:
        st.warning("Please supply both API configurations in the panel interface to compute model queries.")
    else:
        ai_client = OpenAI(api_key=openai_key_input)
        with st.spinner("Initializing scraper array modules across source addresses..."):
            video_targets = fetch_tiktoks(apify_token_input, search_query, max_results)
            
        st.info(f"Target vector set complete: Parsed {len(video_targets)} elements.")
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://www.tiktok.com/"
        }
        
        for idx, item in enumerate(video_targets):
            st.subheader(f"Analyzing Target Stream Vector #{idx+1}")
            st.text(f"Extracted String Metadata: {item['desc']}")
            
            if not item['download_url']:
                st.text("⚠️ Missing accessible direct target link parameters. Continuing buffer cycle...")
                continue
                
            status_ui = st.empty()
            status_ui.text("📥 Caching payload chunk sets locally...")
            local_mp4 = f"temp_item_hash_{os.getpid()}.mp4"
            
            try:
                r = requests.get(item['download_url'], headers=headers, stream=True, timeout=12)
                r.raise_for_status()
                with open(local_mp4, 'wb') as fl:
                    for chunk in r.iter_content(chunk_size=8192):
                        fl.write(chunk)
                        
                flagged, frame_idx = analyze_video_frames(local_mp4, item['desc'], ai_client, status_ui, item['url'])
                if flagged:
                    status_ui.empty()
                    st.error(f"💥 Incident Verified at Sequence Target Frame {frame_idx}")
                    st.link_button("🎯 Open Intelligence Location Source Link", item['url'])
                    if item['url']: 
                        webbrowser.open(item['url'])
                else:
                    status_ui.success("✅ Sequence Array analysis clean. Content labeled safe.")
            except Exception as e:
                st.error(f"Pipeline error event: {e}")
            finally:
                if os.path.exists(local_mp4): os.remove(local_mp4)

# Dynamic Display Component reading from the synchronized logs
st.markdown("---")
st.subheader("📊 Operational Intelligence Feed Logs")

if os.path.exists(CSV_FILE):
    data_matrix = pd.read_csv(CSV_FILE)
    if not data_matrix.empty:
        metric_col1, metric_col2 = st.columns(2)
        metric_col1.metric("Confirmed Risk Incident Captures", len(data_matrix))
        metric_col2.metric("Mean Core Violence Metric Weight", f"{data_matrix['violence'].mean():.3f}")
        
        for _, metric_row in data_matrix.iloc[::-1].iterrows():
            with st.container():
                st.markdown(f"**📍 Source Origin: {metric_row['source']}** • *Timestamp: {str(metric_row['timestamp'])[:19]}*")
                st.markdown(f"📦 **Log Descriptor Context:** {metric_row['title']}")
                st.markdown(f"📊 Content Threat Indices: Violence: `{metric_row['violence']}` | Visual Shock: `{metric_row['graphic']}`")
                st.markdown(f"[🔗 Direct Resource Reference Link]({metric_row['link']})")
                st.markdown("<div style='border-bottom: 1px solid #ddd; margin: 12px 0;'></div>", unsafe_allow_html=True)
    else:
        st.info("System Engine Listening. Verified risk data arrays completely empty for this current operational iteration.")