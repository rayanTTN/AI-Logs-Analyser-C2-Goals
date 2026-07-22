import math
import urllib.parse
import numpy as np
from sklearn.ensemble import IsolationForest
from collections import defaultdict, Counter

def analyze_ip_anomalies(rows, top_ips=None, expected_regions=None):
    top_ips = top_ips or []
    expected_regions = expected_regions or []
    
    if not rows:
        return "No IP has abnormal Spike and all traffic originates from expected regions.", False

    ip_minute_counts = defaultdict(lambda: defaultdict(int))
    for row in rows:
        ip = row.get("client_port", "").rsplit(":", 1)[0]
        ts = row.get("timestamp", "")
        if not ip or not ts: continue
        minute = ts[:16] 
        ip_minute_counts[ip][minute] += 1
        
    data_points = []
    metadata = []
    for ip, minutes in ip_minute_counts.items():
        for minute, count in minutes.items():
            data_points.append([count])
            metadata.append({"ip": ip, "minute": minute, "count": count})
            
    anomalous_ips = {}
    if len(data_points) >= 10:
        clf = IsolationForest(contamination=0.03, random_state=42)
        X = np.array(data_points)
        clf.fit(X)
        preds = clf.predict(X)
        
        for idx, pred in enumerate(preds):
            if pred == -1: 
                meta = metadata[idx]
                ip = meta["ip"]
                count = meta["count"]
                all_counts = list(ip_minute_counts[ip].values())
                avg_count = int(np.mean([c for c in all_counts if c != count] or [1]))
                
                if count > (avg_count * 2): 
                    if ip not in anomalous_ips or count > anomalous_ips[ip]['peak']:
                        anomalous_ips[ip] = {"peak": count, "avg": avg_count}
                        
    geo_warnings = []
    if expected_regions:
        for item in top_ips:
            region = item.get('region', 'Unknown')
            if region != 'Unknown':
                allowed = False
                reg_lower = region.lower()
                for exp in expected_regions:
                    if exp in reg_lower or reg_lower in exp:
                        allowed = True
                        break
                if not allowed:
                    geo_warnings.append(f"<b>{item['ip']}</b> (Location: {region})")
                    
    is_abnormal = False
    summary_parts = []
    
    if anomalous_ips:
        is_abnormal = True
        spike_text = "There is sudden increase in the traffic from the below IP(s)<br>"
        for ip in anomalous_ips.keys():
            spike_text += f"<b>{ip}</b><br>"
            
        extreme_ip = max(anomalous_ips, key=lambda k: anomalous_ips[k]["peak"])
        ext_avg = anomalous_ips[extreme_ip]["avg"]
        ext_peak = anomalous_ips[extreme_ip]["peak"]
        spike_text += f"<br>The count has suddenly increased from {ext_avg} to {ext_peak} which is abnormal as compared to other IP's."
        summary_parts.append(spike_text)
        
    if geo_warnings:
        is_abnormal = True
        geo_text = "<br><br>" if summary_parts else ""
        geo_text += "⚠️ <b>Geographic Anomaly Detected:</b><br>"
        geo_text += "Traffic was detected from unauthorized regions outside your configuration. Please inspect:<br>"
        geo_text += "<br>".join(geo_warnings)
        summary_parts.append(geo_text)
        
    if not is_abnormal:
        return "No IP has abnormal Spike and all top traffic originates from expected regions.", False
        
    return "".join(summary_parts), True

def analyze_5xx_ratio(rows, critical_limit):
    if not rows:
        return "NO IP has 5XX ratio greater then the defined abnormal failure rate", False
    
    ip_counts = defaultdict(lambda: {'total': 0, '5xx': 0})
    for row in rows:
        client_port = row.get("client_port", "")
        if not client_port: continue
        ip = client_port.rsplit(":", 1)[0]
        
        ip_counts[ip]['total'] += 1
        
        elb_status = str(row.get("elb_status_code", ""))
        target_status = str(row.get("target_status_code", ""))
        if elb_status.startswith('5') or target_status.startswith('5'):
            ip_counts[ip]['5xx'] += 1
            
    critical_ips = []
    
    for ip, counts in ip_counts.items():
        if counts['5xx'] > 0 and counts['total'] >= 5: 
            ratio_decimal = counts['5xx'] / counts['total']
            
            if ratio_decimal > critical_limit:
                critical_ips.append({
                    "ip": ip,
                    "total": counts['total'],
                    "5xx": counts['5xx'],
                    "ratio": ratio_decimal * 100
                })
                
    if critical_ips:
        critical_ips.sort(key=lambda x: x['ratio'], reverse=True)
        
        summary = "The following IP(s) have an abnormal 5XX failure rate exceeding the defined limit:<br><br>"
        for item in critical_ips:
            summary += f"• <b>{item['ip']}</b>: {item['5xx']} errors out of {item['total']} requests (<b>{item['ratio']:.2f}%</b>)<br>"
            
        return summary, True
    else:
        return "NO IP has 5XX ratio greater then the defined abnormal failure rate", False

def analyze_latency_anomalies(top_latencies, latency_limit):
    if not top_latencies:
        return "No latency data available for AI analysis.", False
        
    total_count = len(top_latencies)
    ip_counts = Counter(item['ip'] for item in top_latencies)
    url_counts = Counter(item['url'] for item in top_latencies)
    
    major_ip = None
    major_url = None
    
    for ip, count in ip_counts.items():
        if count / total_count >= 0.5:
            major_ip = ip
            break
            
    for url, count in url_counts.items():
        if count / total_count >= 0.5:
            major_url = url
            break
            
    summary = ""
    is_abnormal = False
    
    if major_ip:
        max_lat_for_ip = max([item['latency'] for item in top_latencies if item['ip'] == major_ip])
        if max_lat_for_ip < latency_limit:
            summary += f"A lot of latencies look like they are originating from the same IP: <b>{major_ip}</b>.<br>But the latency of it is below the defined Latency Limit hence this is not suspicious.<br><br>"
        else:
            is_abnormal = True
            summary += f"A lot of latencies look like they are originating from the same IP: <b>{major_ip}</b>. This needs to be checked as it can be because of a request from a far away region, network packet loss, or other technical reasons.<br><br>"
        
    if major_url:
        max_lat_for_url = max([item['latency'] for item in top_latencies if item['url'] == major_url])
        if max_lat_for_url < latency_limit:
            summary += f"Most latencies are from a single URL path: <b><span style='word-break: break-all;'>{major_url}</span></b>.<br>But the latency of it is below the defined Latency Limit hence this is not suspicious."
        else:
            is_abnormal = True
            summary += f"Most latencies are from a single URL path: <b><span style='word-break: break-all;'>{major_url}</span></b>. This needs to be checked if the backend resource or target group hosting this is running slow or is having a resource crunch."
        
    if not summary:
        summary = "The top latencies are distributed across various IPs and URLs. No single IP or backend path appears to be the primary bottleneck, indicating typical network/processing variance."
        
    return summary.strip("<br>"), is_abnormal

def shannon_entropy(data):
    if not data: return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy



def analyze_url_anomalies(top_urls):
    success_msg = "None of the URL's look suspicious. The Top 5XX count URLs also have successful responses or follow standard API architectural patterns, indicating they are real working URL's."
    if not top_urls: return success_msg, False
        
    # Added 'healthcheck', 'health', and 'playback' to broaden the enterprise baseline
    safe_keywords = ['api', 'v1', 'v2', 'v3', 'v4', 'oauth', 'token', 'auth', 'login', 
                     'offset', 'client', 'pub', 'rail', 'service', 'customer', 'payment', 
                     'home', 'details', 'status', 'user', 'account', 'binge', 'live', 'tpf',
                     'healthcheck', 'health', 'playback']
    
    data_points = []
    parsed_data = []
    
    for item in top_urls:
        url_str = item["url"]
        try:
            parsed_url = urllib.parse.urlparse(url_str)
            path = parsed_url.path.lower()
        except:
            path = url_str.lower()
            
        if len(path) < 3: path = "unknown"
            
        raw_entropy = shannon_entropy(path)
        keyword_score = sum(1 for word in safe_keywords if word in path)
        
        vowels = sum(1 for c in path if c in 'aeiou')
        consonants = sum(1 for c in path if c in 'bcdfghjklmnpqrstvwxyz')
        cv_ratio = consonants / (vowels + 1)
        
        parsed_data.append({
            "item": item, "path": path, "raw_entropy": raw_entropy,
            "keyword_score": keyword_score, "cv_ratio": cv_ratio
        })
        data_points.append([raw_entropy, keyword_score, cv_ratio])
        
    malicious_urls = []
    
    if len(data_points) >= 4:
        clf = IsolationForest(contamination=0.15, random_state=42)
        X = np.array(data_points)
        clf.fit(X)
        preds = clf.predict(X)
        
        for idx, pred in enumerate(preds):
            data = parsed_data[idx]
            item = data['item']
            
            if pred == -1 and item['2xx'] == 0:
                # SCENARIO A: 0 safe keywords found. Use standard strict thresholds.
                if data['keyword_score'] == 0 and (data['cv_ratio'] > 2.0 or data['raw_entropy'] > 2.5):
                    malicious_urls.append(item)
                # SCENARIO B: 1 safe keyword found (e.g., just "api"). 
                # Requires severe scrambling to override the safe keyword and flag as malicious.
                elif data['keyword_score'] == 1 and (data['cv_ratio'] > 3.5 or data['raw_entropy'] > 3.8):
                    malicious_urls.append(item)
                
    for data in parsed_data:
        item = data['item']
        if item['2xx'] == 0 and item not in malicious_urls:
            if data['keyword_score'] == 0:
                if data['cv_ratio'] > 2.5 or data['raw_entropy'] > 2.8:
                    malicious_urls.append(item)
            
    if not malicious_urls: return success_msg, False
        
    summary = "AI Model detected highly anomalous, random-typed URL paths with zero successful (2XX) responses. This indicates a probable Directory Traversal or DDoS scan:<br><br>"
    suspicious_ips = set()
    
    for m in malicious_urls:
        summary += f"<b>Suspicious URL:</b> <span style='word-break: break-all;'>{m['url']}</span><br>"
        suspicious_ips.update(m['ips'])
        
    summary += "<br><b>Malicious IPs to Block immediately:</b><br>"
    for ip in suspicious_ips:
        summary += f"<span style='color: #ef4444; font-weight: 600;'>{ip}</span><br>"
        
    return summary, True





# def analyze_url_anomalies(top_urls):
#     success_msg = "None of the URL's look suspicious. The Top 5XX count URLs also have successful responses or follow standard API architectural patterns, indicating they are real working URL's."
#     if not top_urls: return success_msg, False
        
#     safe_keywords = ['api', 'v1', 'v2', 'v3', 'v4', 'oauth', 'token', 'auth', 'login', 
#                      'offset', 'client', 'pub', 'rail', 'service', 'customer', 'payment', 
#                      'home', 'details', 'status', 'user', 'account', 'binge', 'live', 'tpf']
    
#     data_points = []
#     parsed_data = []
    
#     for item in top_urls:
#         url_str = item["url"]
#         try:
#             parsed_url = urllib.parse.urlparse(url_str)
#             path = parsed_url.path.lower()
#         except:
#             path = url_str.lower()
            
#         if len(path) < 3: path = "unknown"
            
#         # Refined Math: Relying on Raw Entropy instead of Norm Entropy
#         raw_entropy = shannon_entropy(path)
#         keyword_score = sum(1 for word in safe_keywords if word in path)
        
#         vowels = sum(1 for c in path if c in 'aeiou')
#         consonants = sum(1 for c in path if c in 'bcdfghjklmnpqrstvwxyz')
#         cv_ratio = consonants / (vowels + 1)
        
#         parsed_data.append({
#             "item": item, "path": path, "raw_entropy": raw_entropy,
#             "keyword_score": keyword_score, "cv_ratio": cv_ratio
#         })
#         data_points.append([raw_entropy, keyword_score, cv_ratio])
        
#     malicious_urls = []
    
#     # 1. ML Isolation Forest Catch
#     if len(data_points) >= 4:
#         clf = IsolationForest(contamination=0.15, random_state=42)
#         X = np.array(data_points)
#         clf.fit(X)
#         preds = clf.predict(X)
        
#         for idx, pred in enumerate(preds):
#             data = parsed_data[idx]
#             item = data['item']
#             # Strict Gating: Must be an ML outlier AND 100% fail rate
#             if pred == -1 and item['2xx'] == 0:
#                 # Lenient threshold because the ML already flagged it
#                 if data['keyword_score'] <= 1 and (data['cv_ratio'] > 2.0 or data['raw_entropy'] > 2.5):
#                     malicious_urls.append(item)
                
#     # 2. Heuristic Safety Net Catch (In case ML misses it)
#     for data in parsed_data:
#         item = data['item']
#         if item['2xx'] == 0 and item not in malicious_urls:
#             # If it has NO safe architectural keywords at all
#             if data['keyword_score'] == 0:
#                 # Catch Keyboard Smashes (CV > 2.5) OR High Chaos Strings (Entropy > 2.8)
#                 if data['cv_ratio'] > 2.5 or data['raw_entropy'] > 2.8:
#                     malicious_urls.append(item)
            
#     if not malicious_urls: return success_msg, False
        
#     summary = "AI Model detected highly anomalous, random-typed URL paths with zero successful (2XX) responses. This indicates a probable Directory Traversal or DDoS scan:<br><br>"
#     suspicious_ips = set()
    
#     for m in malicious_urls:
#         summary += f"<b>Suspicious URL:</b> <span style='word-break: break-all;'>{m['url']}</span><br>"
#         suspicious_ips.update(m['ips'])
        
#     summary += "<br><b>Malicious IPs to Block immediately:</b><br>"
#     for ip in suspicious_ips:
#         summary += f"<span style='color: #ef4444; font-weight: 600;'>{ip}</span><br>"
        
#     return summary, True
