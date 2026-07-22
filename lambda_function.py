import json
import os
import gzip
import csv
import io
import time
import traceback
import concurrent.futures
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import boto3
import urllib.request

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

from graph_generator import generate_top_ips_chart, generate_5xx_chart, generate_latency_ip_chart, generate_latency_url_chart, generate_url_5xx_chart, generate_url_2xx_chart
from ai_analyzer import analyze_ip_anomalies, analyze_5xx_ratio, analyze_latency_anomalies, analyze_url_anomalies

# ---- Global Configuration ----
s3_client = boto3.client("s3")
ses_client = boto3.client("ses", region_name=os.environ.get("AWS_REGION", "ap-south-1"))

TOP_IP_LIMIT = int(os.environ.get("TOP_IP_LIMIT", "20"))
TOP_5XX_LIMIT = int(os.environ.get("TOP_5XX_LIMIT", "20"))
TOP_IP_URL_LATENCY = int(os.environ.get("TOP_IP_URL_LATENCY", "10"))
TOP_URL_5XX_LIMIT = int(os.environ.get("TOP-URL-5XX", os.environ.get("TOP_URL_5XX", "10")))
MAX_TIMEFRAME_MINUTES = int(os.environ.get("MAX_TIMEFRAME_MINUTES", "45"))

EXPECTED_REGIONS = [r.strip().lower() for r in os.environ.get("EXPECTED_REGIONS", "").split(",") if r.strip()]

# Parse 5XX Limit accurately against the AWS Console Variable name
raw_limit_5xx = os.environ.get("FAILURE_5XX_CRITICAL_LIMIT", os.environ.get("5XX_FAILURE_CRITICAL_LIMIT", "0.05"))
try:
    LIMIT_5XX_CRITICAL = float(raw_limit_5xx)
except ValueError:
    LIMIT_5XX_CRITICAL = 0.05

raw_limit_lat = os.environ.get("LATENCY_LIMIT", "10.0")
try:
    LATENCY_LIMIT = float(raw_limit_lat)
except ValueError:
    LATENCY_LIMIT = 10.0

FROM_EMAIL = os.environ.get("FROM_EMAIL", "")
TO_EMAIL = os.environ.get("TO_EMAIL", "")
CC_EMAIL = os.environ.get("CC_EMAIL", "")

IST_OFFSET = timedelta(hours=5, minutes=30)
EXPECTED_FORMAT = "%Y-%m-%d %H:%M:%S"
EXPECTED_FORMAT_HINT = "YYYY-MM-DD HH:MM:SS"

# ---- Helper Functions ----
def format_large_number(num):
    if num >= 1_000_000: return f"{num / 1_000_000:.1f}M"
    elif num >= 1_000: return f"{num / 1_000:.1f}k"
    return str(num)

def validate_request(body):
    start_ist = body.get("start_time_ist")
    end_ist = body.get("end_time_ist")
    s3_path = body.get("s3_path")
    if not s3_path: return False, "'s3_path' is required.", None, None, None
    if not start_ist or not end_ist: return False, "Both start/end time required.", None, None, None
    try:
        start_dt = datetime.strptime(start_ist, EXPECTED_FORMAT)
        end_dt = datetime.strptime(end_ist, EXPECTED_FORMAT)
    except ValueError:
        return False, f"Time format incorrect. Use: {EXPECTED_FORMAT_HINT}", None, None, None
    if start_dt >= end_dt: return False, "'start_time_ist' must be earlier.", None, None, None
    
    duration_minutes = (end_dt - start_dt).total_seconds() / 60
    if duration_minutes > MAX_TIMEFRAME_MINUTES:
        return False, f"Time range too large. Max {MAX_TIMEFRAME_MINUTES} mins.", None, None, None
    return True, None, start_ist, end_ist, s3_path

def parse_s3_path(s3_path):
    path = s3_path.strip()
    if path.startswith("s3://"): path = path[len("s3://"):]
    parts = path.split("/", 1)
    bucket = parts[0]
    prefix = parts[1] if len(parts) > 1 else ""
    if prefix and not prefix.endswith("/"): prefix += "/"
    return bucket, prefix

def ist_str_to_utc(ist_str):
    ist_dt = datetime.strptime(ist_str, EXPECTED_FORMAT)
    return ist_dt - IST_OFFSET

def list_matching_objects(bucket, prefix, start_utc, end_utc):
    matching_keys = []
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            last_modified_utc = obj["LastModified"].replace(tzinfo=None)
            if start_utc <= last_modified_utc <= end_utc:
                matching_keys.append(obj["Key"])
    return matching_keys

def parse_single_file(bucket, key, fieldnames):
    rows = []
    obj = s3_client.get_object(Bucket=bucket, Key=key)
    with gzip.GzipFile(fileobj=obj["Body"]) as gz:
        text_stream = io.TextIOWrapper(gz, encoding="utf-8")
        reader = csv.reader(text_stream, delimiter=" ", quotechar='"')
        for parts in reader:
            if parts: rows.append(dict(zip(fieldnames, parts)))
    return rows

def fetch_and_parse_logs(bucket, keys):
    fieldnames = [
        "type", "timestamp", "elb", "client_port", "target_port",
        "request_processing_time", "target_processing_time",
        "response_processing_time", "elb_status_code", "target_status_code",
        "received_bytes", "sent_bytes", "request", "user_agent",
        "ssl_cipher", "ssl_protocol", "target_group_arn", "trace_id",
        "domain_name", "chosen_cert_arn", "matched_rule_priority",
        "request_creation_time", "actions_executed", "redirect_url",
        "error_reason", "target_port_list", "target_status_code_list",
        "classification", "classification_reason"
    ]
    all_rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(parse_single_file, bucket, key, fieldnames) for key in keys]
        for future in concurrent.futures.as_completed(futures):
            all_rows.extend(future.result())
    return all_rows

def extract_client_ip(row):
    client_port = row.get("client_port", "")
    return client_port.rsplit(":", 1)[0] if ":" in client_port else client_port

def get_ip_region(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country"
        req = urllib.request.Request(url, headers={'User-Agent': 'AWS-Lambda-Report'})
        with urllib.request.urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode())
            if data.get("country"):
                return data.get("country")
    except Exception:
        pass
    return "Unknown"

def top_ip_checker(rows, top_n=TOP_IP_LIMIT):
    ip_counter = Counter(extract_client_ip(r) for r in rows if r.get("client_port"))
    return [{"ip": ip, "hits": count} for ip, count in ip_counter.most_common(top_n)]

def get_5xx_data(rows, top_n=TOP_5XX_LIMIT):
    counter_5xx = Counter()
    full_counts = defaultdict(lambda: {'2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0})
    total_5xx = 0
    for row in rows:
        ip = extract_client_ip(row)
        if not ip: continue
        elb_status = str(row.get("elb_status_code", ""))
        target_status = str(row.get("target_status_code", ""))
        
        if elb_status.startswith('5') or target_status.startswith('5'):
            full_counts[ip]['5xx'] += 1
            counter_5xx[ip] += 1
            total_5xx += 1
        elif elb_status.startswith('4') or target_status.startswith('4'):
            full_counts[ip]['4xx'] += 1
        elif elb_status.startswith('3') or target_status.startswith('3'):
            full_counts[ip]['3xx'] += 1
        elif elb_status.startswith('2') or target_status.startswith('2'):
            full_counts[ip]['2xx'] += 1
            
    top_5xx_ips = []
    for ip, count in counter_5xx.most_common(top_n):
        top_5xx_ips.append({
            "ip": ip, "2xx": full_counts[ip]['2xx'], "3xx": full_counts[ip]['3xx'],
            "4xx": full_counts[ip]['4xx'], "5xx": count
        })
    return top_5xx_ips, total_5xx

def get_top_latencies(rows, top_n):
    latency_data = []
    for row in rows:
        try:
            req_time = float(row.get("request_processing_time", 0))
            tgt_time = float(row.get("target_processing_time", 0))
            res_time = float(row.get("response_processing_time", 0))
            req_time = 0 if req_time < 0 else req_time
            tgt_time = 0 if tgt_time < 0 else tgt_time
            res_time = 0 if res_time < 0 else res_time
            total_latency = req_time + tgt_time + res_time
            
            if total_latency > 0:
                ip = extract_client_ip(row)
                request_line = row.get("request", "")
                parts = request_line.split(" ")
                url = parts[1] if len(parts) > 1 else request_line
                latency_data.append({"ip": ip, "url": url, "latency": round(total_latency, 3)})
        except ValueError: continue
            
    latency_data.sort(key=lambda x: x["latency"], reverse=True)
    return latency_data[:top_n]

def get_url_5xx_data(rows, top_n):
    url_stats = defaultdict(lambda: {'2xx': 0, '5xx': 0, 'ips': set()})
    for row in rows:
        req = row.get("request", "")
        parts = req.split(" ")
        url = parts[1] if len(parts) > 1 else req
        
        elb_status = str(row.get("elb_status_code", ""))
        target_status = str(row.get("target_status_code", ""))
        ip = extract_client_ip(row)
        
        if elb_status.startswith('5') or target_status.startswith('5'):
            url_stats[url]['5xx'] += 1
            if ip: url_stats[url]['ips'].add(ip)
        elif elb_status.startswith('2') or target_status.startswith('2'):
            url_stats[url]['2xx'] += 1
            
    sorted_urls = sorted(url_stats.items(), key=lambda x: x[1]['5xx'], reverse=True)
    top_urls = []
    for url, stats in sorted_urls[:top_n]:
        if stats['5xx'] > 0:
            top_urls.append({"url": url, "2xx": stats['2xx'], "5xx": stats['5xx'], "ips": list(stats['ips'])})
    return top_urls


def send_email_report(result):
    if not FROM_EMAIL or not TO_EMAIL:
        raise ValueError("Environment variables 'FROM_EMAIL' and 'TO_EMAIL' are missing.")

    msg = MIMEMultipart('related')
    current_ist = datetime.now() + IST_OFFSET
    timestamp_str = current_ist.strftime("%Y-%m-%d %H:%M:%S")
    msg['Subject'] = f'ALB Log Analysis Report - {timestamp_str} IST'
    msg['From'] = FROM_EMAIL.strip()
    to_addresses = [email.strip() for email in TO_EMAIL.split(",") if email.strip()]
    cc_addresses = [email.strip() for email in CC_EMAIL.split(",") if email.strip()] if CC_EMAIL else []
    msg['To'] = ", ".join(to_addresses)
    if cc_addresses: msg['Cc'] = ", ".join(cc_addresses)
    
    msg_alternative = MIMEMultipart('alternative')
    msg.attach(msg_alternative)

    rows_html = "".join([f'''
        <tr style="border-bottom: 1px solid #e5e7eb;">
            <td style="padding: 10px 0; font-family: monospace; color: #2563eb;">{item["ip"]}</td>
            <td style="padding: 10px 0; font-size: 13px; color: #4b5563;">{item.get("region", "Unknown")}</td>
            <td style="padding: 10px 0; text-align: right; font-weight: 500;">{item["hits"]}</td>
        </tr>''' for item in result['top_ips']]) if result['top_ips'] else '<tr><td colspan="3" style="padding: 10px 0; color: #6b7280;">No data found.</td></tr>'
    
    rows_5xx_html = "".join([f'''
        <tr style="border-bottom: 1px solid #e5e7eb;">
            <td style="padding: 10px 0; font-family: monospace; color: #2563eb; text-align: left;">{item["ip"]}</td>
            <td style="padding: 10px 0; text-align: center; font-weight: 500; color: #10b981;">{item["2xx"]}</td>
            <td style="padding: 10px 0; text-align: center; font-weight: 500; color: #d97706;">{item["3xx"]}</td>
            <td style="padding: 10px 0; text-align: center; font-weight: 500; color: #3b82f6;">{item["4xx"]}</td>
            <td style="padding: 10px 0; text-align: center; font-weight: 600; color: #ef4444;">{item["5xx"]}</td>
        </tr>''' for item in result['top_5xx_ips']]) if result['top_5xx_ips'] else '<tr><td colspan="5" style="padding: 10px 0; color: #6b7280; text-align: center;">No 5XX errors found.</td></tr>'
    
    rows_lat_html = "".join([f'<tr style="border-bottom: 1px solid #e5e7eb;"><td style="padding: 10px 0; font-family: monospace; color: #2563eb;">{item["ip"]}</td><td style="padding: 10px 0; font-weight: 500;">{item["latency"]}s</td><td style="padding: 10px 0; font-size: 12px; color: #6b7280; word-break: break-all;">{item["url"]}</td></tr>' for item in result['top_latencies']]) if result['top_latencies'] else '<tr><td colspan="3" style="padding: 10px 0; color: #6b7280;">No latency data found.</td></tr>'

    rows_url_html = "".join([f'''
        <tr style="border-bottom: 1px solid #e5e7eb;">
            <td style="padding: 10px 0; font-size: 12px; color: #2563eb; word-break: break-all;">{item["url"]}</td>
            <td style="padding: 10px 0; text-align: center; font-weight: 500; color: #10b981;">{item["2xx"]}</td>
            <td style="padding: 10px 0; text-align: center; font-weight: 600; color: #ef4444;">{item["5xx"]}</td>
        </tr>''' for item in result['top_urls_5xx']]) if result['top_urls_5xx'] else '<tr><td colspan="3" style="padding: 10px 0; color: #6b7280; text-align: center;">No 5XX URLs found.</td></tr>'

    total_req_formatted = format_large_number(result['total_requests_parsed'])
    total_5xx_formatted = format_large_number(result['total_5xx_count'])
    max_latency_val = result['top_latencies'][0]['latency'] if result['top_latencies'] else 0
    total_latency_formatted = f"{max_latency_val}s" if max_latency_val > 0 else "0s"

    html_content = f'''
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1f2937; background-color: #f3f4f6; padding: 30px 15px;">
      <div style="max-width: 800px; margin: 0 auto;">
        
        <h2 style="color: #111827; margin-bottom: 20px; font-weight: 600;">ALB Log Analysis Report</h2>
        
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom: 20px;">
          <tr>
            <td width="55%" valign="top" style="padding-right: 10px;">
              <div style="background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                <h4 style="margin-top: 0; margin-bottom: 15px; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">Execution Summary</h4>
                <table style="width: 100%; font-size: 13px; line-height: 1.6;">
                  <tr><td style="padding: 4px 0; color: #6b7280; width: 40%;">Time Range (IST)</td><td style="font-weight: 500;">{result['range_ist']['start']} - {result['range_ist']['end']}</td></tr>
                  <tr><td style="padding: 4px 0; color: #6b7280;">S3 Bucket Name</td><td style="font-weight: 500;">{result['s3_bucket']}</td></tr>
                  <tr><td style="padding: 4px 0; color: #6b7280;">Execution Time</td><td style="font-weight: 500;">{result['execution_time']}</td></tr>
                  <tr><td style="padding: 4px 0; color: #6b7280;">Log Files Analysed</td><td style="font-weight: 500;">{result['files_matched']}</td></tr>
                </table>
              </div>
            </td>
            <td width="45%" valign="top" style="padding-left: 10px;">
              <div style="background-color: #ffffff; border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                <h4 style="margin-top: 0; margin-bottom: 15px; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">Traffic Metrics</h4>
                <table style="width: 100%; font-size: 13px; line-height: 1.6;">
                  <tr><td style="padding: 4px 0; color: #6b7280; width: 45%;">Total Requests</td><td style="font-weight: 600; color: #047857; font-size: 14px;">{total_req_formatted}</td></tr>
                  <tr><td style="padding: 4px 0; color: #6b7280;">Total 5XX Hits</td><td style="font-weight: 600; color: #ef4444; font-size: 14px;">{total_5xx_formatted}</td></tr>
                  <tr><td style="padding: 4px 0; color: #6b7280;">Top Latency</td><td style="font-weight: 600; color: #f59e0b; font-size: 14px;">{total_latency_formatted}</td></tr>
                </table>
              </div>
            </td>
          </tr>
        </table>
        
        <div style="background-color: #ffffff; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
          <h4 style="margin-top: 0; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">Top Offending IPs</h4>
          <table style="width: 100%; border-collapse: collapse; font-size: 14px; text-align: left; margin-bottom: 20px;">
            <thead>
              <tr style="border-bottom: 2px solid #e5e7eb;">
                <th style="padding: 10px 0; font-weight: 600;">IP Address</th>
                <th style="padding: 10px 0; font-weight: 600;">Region</th>
                <th style="padding: 10px 0; font-weight: 600; text-align: right;">Total Hits</th>
              </tr>
            </thead>
            <tbody>
              {rows_html}
            </tbody>
          </table>
          <div style="text-align: center; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
            <img src="cid:top_ips_graph" alt="Top IPs Graph" style="width: 100%; max-width: 600px; height: auto;">
          </div>
          <div style="background-color: #f8fafc; border-left: 4px solid {result['ip_border_color']}; padding: 15px; margin-top: 20px; border-radius: 4px;">
            <h4 style="margin-top: 0; color: #6b7280; font-size: 12px; text-transform: uppercase; margin-bottom: 8px;">AI Analysis</h4>
            <p style="font-size: 14px; line-height: 1.6; color: #374151; margin-bottom: 0;">
                {result['ai_ip_summary']}
            </p>
          </div>
        </div>
        
        <div style="background-color: #ffffff; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
          <h4 style="margin-top: 0; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">Top IPs by 5XX Errors</h4>
          <table style="width: 100%; border-collapse: collapse; font-size: 14px; margin-bottom: 20px;">
            <thead>
              <tr style="border-bottom: 2px solid #e5e7eb;">
                <th style="padding: 10px 0; font-weight: 600; text-align: left;">IP Address</th>
                <th style="padding: 10px 0; font-weight: 600; text-align: center; color: #10b981;">2XX</th>
                <th style="padding: 10px 0; font-weight: 600; text-align: center; color: #d97706;">3XX</th>
                <th style="padding: 10px 0; font-weight: 600; text-align: center; color: #3b82f6;">4XX</th>
                <th style="padding: 10px 0; font-weight: 600; text-align: center; color: #ef4444;">5XX</th>
              </tr>
            </thead>
            <tbody>
              {rows_5xx_html}
            </tbody>
          </table>
          <div style="text-align: center; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
            <img src="cid:top_5xx_graph" alt="Top 5XX Graph" style="width: 100%; max-width: 600px; height: auto;">
          </div>
          <div style="background-color: #f8fafc; border-left: 4px solid {result['fxx_border_color']}; padding: 15px; margin-top: 20px; border-radius: 4px;">
            <h4 style="margin-top: 0; color: #6b7280; font-size: 12px; text-transform: uppercase; margin-bottom: 8px;">AI Analysis (5XX Ratio)</h4>
            <p style="font-size: 14px; line-height: 1.6; color: #374151; margin-bottom: 0;">
                {result['ai_5xx_summary']}
            </p>
          </div>
        </div>
        
        <div style="background-color: #ffffff; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
          <h4 style="margin-top: 0; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">Top Latency IPs and URLs</h4>
          <table style="width: 100%; border-collapse: collapse; font-size: 14px; text-align: left; margin-bottom: 20px;">
            <thead>
              <tr style="border-bottom: 2px solid #e5e7eb;">
                <th style="padding: 10px 0; font-weight: 600; width: 25%;">IP Address</th>
                <th style="padding: 10px 0; font-weight: 600; width: 15%;">Latency</th>
                <th style="padding: 10px 0; font-weight: 600; width: 60%;">URL</th>
              </tr>
            </thead>
            <tbody>
              {rows_lat_html}
            </tbody>
          </table>
          <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
            <tr>
              <td width="50%" align="center" style="padding-right: 10px;">
                <img src="cid:latency_ip_graph" alt="Latency vs IP Graph" style="width: 100%; max-width: 380px; height: auto;">
              </td>
              <td width="50%" align="center" style="padding-left: 10px;">
                <img src="cid:latency_url_graph" alt="Latency vs URL Graph" style="width: 100%; max-width: 380px; height: auto;">
              </td>
            </tr>
          </table>
          <div style="background-color: #f8fafc; border-left: 4px solid {result['lat_border_color']}; padding: 15px; margin-top: 20px; border-radius: 4px;">
            <h4 style="margin-top: 0; color: #6b7280; font-size: 12px; text-transform: uppercase; margin-bottom: 8px;">AI Analysis</h4>
            <p style="font-size: 14px; line-height: 1.6; color: #374151; margin-bottom: 0;">
                {result['ai_lat_summary']}
            </p>
          </div>
        </div>
        
        <div style="background-color: #ffffff; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
          <h4 style="margin-top: 0; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">URLs with Top 5XX Errors</h4>
          <table style="width: 100%; border-collapse: collapse; font-size: 14px; text-align: left; margin-bottom: 20px;">
            <thead>
              <tr style="border-bottom: 2px solid #e5e7eb;">
                <th style="padding: 10px 0; font-weight: 600; width: 60%;">URL</th>
                <th style="padding: 10px 0; font-weight: 600; text-align: center; color: #10b981;">2XX Count</th>
                <th style="padding: 10px 0; font-weight: 600; text-align: center; color: #ef4444;">5XX Count</th>
              </tr>
            </thead>
            <tbody>
              {rows_url_html}
            </tbody>
          </table>
          <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
            <tr>
              <td width="50%" align="center" style="padding-right: 10px;">
                <img src="cid:url_5xx_graph" alt="5XX vs URL Graph" style="width: 100%; max-width: 380px; height: auto;">
              </td>
              <td width="50%" align="center" style="padding-left: 10px;">
                <img src="cid:url_2xx_graph" alt="2XX vs URL Graph" style="width: 100%; max-width: 380px; height: auto;">
              </td>
            </tr>
          </table>
          <div style="background-color: #f8fafc; border-left: 4px solid {result['url_border_color']}; padding: 15px; margin-top: 20px; border-radius: 4px;">
            <h4 style="margin-top: 0; color: #6b7280; font-size: 12px; text-transform: uppercase; margin-bottom: 8px;">AI Analysis</h4>
            <p style="font-size: 14px; line-height: 1.6; color: #374151; margin-bottom: 0;">
                {result['ai_url_summary']}
            </p>
          </div>
        </div>

      </div>
    </div>
    '''
    
    msg_alternative.attach(MIMEText(html_content, 'html'))

    chart_bytes_ip = generate_top_ips_chart(result['top_ips'])
    if chart_bytes_ip:
        img1 = MIMEImage(chart_bytes_ip)
        img1.add_header('Content-ID', '<top_ips_graph>')
        img1.add_header('Content-Disposition', 'inline', filename='top_ips.png')
        msg.attach(img1)
        
    chart_bytes_5xx = generate_5xx_chart(result['top_5xx_ips'])
    if chart_bytes_5xx:
        img2 = MIMEImage(chart_bytes_5xx)
        img2.add_header('Content-ID', '<top_5xx_graph>')
        img2.add_header('Content-Disposition', 'inline', filename='top_5xx.png')
        msg.attach(img2)
        
    chart_bytes_lat_ip = generate_latency_ip_chart(result['top_latencies'])
    if chart_bytes_lat_ip:
        img3 = MIMEImage(chart_bytes_lat_ip)
        img3.add_header('Content-ID', '<latency_ip_graph>')
        img3.add_header('Content-Disposition', 'inline', filename='lat_ip.png')
        msg.attach(img3)
        
    chart_bytes_lat_url = generate_latency_url_chart(result['top_latencies'])
    if chart_bytes_lat_url:
        img4 = MIMEImage(chart_bytes_lat_url)
        img4.add_header('Content-ID', '<latency_url_graph>')
        img4.add_header('Content-Disposition', 'inline', filename='lat_url.png')
        msg.attach(img4)
        
    chart_bytes_url_5xx = generate_url_5xx_chart(result['top_urls_5xx'])
    if chart_bytes_url_5xx:
        img5 = MIMEImage(chart_bytes_url_5xx)
        img5.add_header('Content-ID', '<url_5xx_graph>')
        img5.add_header('Content-Disposition', 'inline', filename='url_5xx.png')
        msg.attach(img5)
        
    chart_bytes_url_2xx = generate_url_2xx_chart(result['top_urls_5xx'])
    if chart_bytes_url_2xx:
        img6 = MIMEImage(chart_bytes_url_2xx)
        img6.add_header('Content-ID', '<url_2xx_graph>')
        img6.add_header('Content-Disposition', 'inline', filename='url_2xx.png')
        msg.attach(img6)

    all_destinations = to_addresses + cc_addresses
    ses_client.send_raw_email(Source=FROM_EMAIL.strip(), Destinations=all_destinations, RawMessage={'Data': msg.as_string()})

def lambda_handler(event, context):
    lambda_start_time = time.time()
    try:
        body_str = event.get("body", "{}")
        body = json.loads(body_str)

        is_valid, error_msg, start_ist, end_ist, s3_path = validate_request(body)
        if not is_valid: return {"statusCode": 400, "body": json.dumps({"error": error_msg})}

        bucket, prefix = parse_s3_path(s3_path)
        start_utc = ist_str_to_utc(start_ist)
        end_utc = ist_str_to_utc(end_ist)
        
        keys = list_matching_objects(bucket, prefix, start_utc, end_utc)
        rows = fetch_and_parse_logs(bucket, keys) if keys else []
        
        top_ips = top_ip_checker(rows, top_n=TOP_IP_LIMIT) if rows else []
        for item in top_ips:
            item['region'] = get_ip_region(item['ip'])
            
        top_5xx_ips, total_5xx = get_5xx_data(rows, top_n=TOP_5XX_LIMIT) if rows else ([], 0)
        top_latencies = get_top_latencies(rows, top_n=TOP_IP_URL_LATENCY) if rows else []
        top_urls_5xx = get_url_5xx_data(rows, top_n=TOP_URL_5XX_LIMIT) if rows else []
        
        ai_ip_summary_text, is_ip_abnormal = analyze_ip_anomalies(rows, top_ips, EXPECTED_REGIONS)
        ai_5xx_summary_text, is_5xx_critical = analyze_5xx_ratio(rows, LIMIT_5XX_CRITICAL)
        ai_lat_summary_text, is_lat_abnormal = analyze_latency_anomalies(top_latencies, LATENCY_LIMIT)
        ai_url_summary_text, is_url_abnormal = analyze_url_anomalies(top_urls_5xx)

        ip_border_color = "#ef4444" if is_ip_abnormal else "#3b82f6" 
        fxx_border_color = "#ef4444" if is_5xx_critical else "#10b981" 
        lat_border_color = "#ef4444" if is_lat_abnormal else "#10b981" 
        url_border_color = "#ef4444" if is_url_abnormal else "#10b981" 

        duration = time.time() - lambda_start_time
        if duration >= 60:
            mins, secs = int(duration // 60), int(duration % 60)
            execution_time_str = f"{mins} mins {secs} secs"
        else:
            execution_time_str = f"{duration:.2f} secs"

        result = {
            "range_ist": {"start": start_ist, "end": end_ist},
            "s3_bucket": bucket,
            "files_matched": len(keys),
            "execution_time": execution_time_str,
            "total_requests_parsed": len(rows),
            "total_5xx_count": total_5xx,
            "top_ips": top_ips,
            "top_5xx_ips": top_5xx_ips,
            "top_latencies": top_latencies,
            "top_urls_5xx": top_urls_5xx,
            "ai_ip_summary": ai_ip_summary_text,
            "ai_5xx_summary": ai_5xx_summary_text,
            "ai_lat_summary": ai_lat_summary_text,
            "ai_url_summary": ai_url_summary_text,
            "ip_border_color": ip_border_color,
            "fxx_border_color": fxx_border_color,
            "lat_border_color": lat_border_color,
            "url_border_color": url_border_color
        }

        send_email_report(result)
        return {"statusCode": 200, "headers": {"Content-Type": "application/json"}, "body": json.dumps({"message": "Log parsing complete. AI Report emailed."})}
    except Exception as e:
        return {"statusCode": 500, "headers": {"Content-Type": "application/json"}, "body": json.dumps({"error_type": type(e).__name__, "error_message": str(e), "traceback": traceback.format_exc()})}
