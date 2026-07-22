import json
import urllib.request
import urllib.parse

def generate_top_ips_chart(top_ips):
    if not top_ips: return None
    labels = [item['ip'] for item in top_ips]
    data = [item['hits'] for item in top_ips]
    chart_config = {
        "type": "bar",
        "data": {
            "labels": labels,
            "datasets": [{"label": "Total Hits", "data": data, "backgroundColor": "#3b82f6", "borderRadius": 4}]
        },
        "options": {
            "plugins": {"title": {"display": True, "text": "Top Offending IPs", "font": {"size": 16}}, "legend": {"display": False}},
            "scales": {"y": {"beginAtZero": True}}
        }
    }
    encoded_config = urllib.parse.quote(json.dumps(chart_config))
    url = f"https://quickchart.io/chart?w=800&h=400&c={encoded_config}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'AWS-Lambda-Report'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read()
    except Exception: return None

def generate_5xx_chart(top_5xx):
    if not top_5xx: return None
    labels = [item['ip'] for item in top_5xx]
    data_2xx = [item['2xx'] for item in top_5xx]
    data_3xx = [item['3xx'] for item in top_5xx]
    data_4xx = [item['4xx'] for item in top_5xx]
    data_5xx = [item['5xx'] for item in top_5xx]
    chart_config = {
        "type": "bar",
        "data": {
            "labels": labels,
            "datasets": [
                {"label": "2XX", "data": data_2xx, "backgroundColor": "#10b981", "borderRadius": 2},
                {"label": "3XX", "data": data_3xx, "backgroundColor": "#d97706", "borderRadius": 2},
                {"label": "4XX", "data": data_4xx, "backgroundColor": "#3b82f6", "borderRadius": 2},
                {"label": "5XX", "data": data_5xx, "backgroundColor": "#ef4444", "borderRadius": 2}
            ]
        },
        "options": {
            "plugins": {"title": {"display": True, "text": "Status Code Breakdown for Top 5XX IPs", "font": {"size": 16}}, "legend": {"display": True, "position": "bottom"}},
            "scales": {"y": {"beginAtZero": True}}
        }
    }
    encoded_config = urllib.parse.quote(json.dumps(chart_config))
    url = f"https://quickchart.io/chart?w=800&h=400&c={encoded_config}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'AWS-Lambda-Report'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read()
    except Exception: return None

def generate_latency_ip_chart(top_latencies):
    if not top_latencies: return None
    labels = [item['ip'] for item in top_latencies]
    data = [item['latency'] for item in top_latencies]
    chart_config = {
        "type": "bar",
        "data": {"labels": labels, "datasets": [{"label": "Latency (s)", "data": data, "backgroundColor": "#3b82f6", "borderRadius": 4}]},
        "options": {"plugins": {"title": {"display": True, "text": "Latency vs IP", "font": {"size": 14}}, "legend": {"display": False}}, "scales": {"y": {"beginAtZero": True}}}
    }
    encoded_config = urllib.parse.quote(json.dumps(chart_config))
    url = f"https://quickchart.io/chart?w=400&h=300&c={encoded_config}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'AWS-Lambda-Report'})
        with urllib.request.urlopen(req, timeout=10) as response: return response.read()
    except Exception: return None

def generate_latency_url_chart(top_latencies):
    if not top_latencies: return None
    labels = []
    for item in top_latencies:
        try:
            path = urllib.parse.urlparse(item['url']).path
            if len(path) > 15: path = ".." + path[-13:]
            labels.append(path if path else "URL")
        except: labels.append("URL")
    data = [item['latency'] for item in top_latencies]
    chart_config = {
        "type": "bar",
        "data": {"labels": labels, "datasets": [{"label": "Latency (s)", "data": data, "backgroundColor": "#3b82f6", "borderRadius": 4}]},
        "options": {"plugins": {"title": {"display": True, "text": "Latency vs URL", "font": {"size": 14}}, "legend": {"display": False}}, "scales": {"y": {"beginAtZero": True}}}
    }
    encoded_config = urllib.parse.quote(json.dumps(chart_config))
    url = f"https://quickchart.io/chart?w=400&h=300&c={encoded_config}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'AWS-Lambda-Report'})
        with urllib.request.urlopen(req, timeout=10) as response: return response.read()
    except Exception: return None

def generate_url_5xx_chart(top_urls):
    if not top_urls: return None
    labels = []
    for item in top_urls:
        try:
            path = urllib.parse.urlparse(item['url']).path
            if len(path) > 15: path = ".." + path[-13:]
            labels.append(path if path else "URL")
        except: labels.append("URL")
    data = [item['5xx'] for item in top_urls]
    chart_config = {
        "type": "bar",
        "data": {"labels": labels, "datasets": [{"label": "5XX Count", "data": data, "backgroundColor": "#ef4444", "borderRadius": 4}]},
        "options": {"plugins": {"title": {"display": True, "text": "5XX Count vs URL", "font": {"size": 14}}, "legend": {"display": False}}, "scales": {"y": {"beginAtZero": True}}}
    }
    encoded_config = urllib.parse.quote(json.dumps(chart_config))
    url = f"https://quickchart.io/chart?w=400&h=300&c={encoded_config}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'AWS-Lambda-Report'})
        with urllib.request.urlopen(req, timeout=10) as response: return response.read()
    except Exception: return None

def generate_url_2xx_chart(top_urls):
    if not top_urls: return None
    labels = []
    for item in top_urls:
        try:
            path = urllib.parse.urlparse(item['url']).path
            if len(path) > 15: path = ".." + path[-13:]
            labels.append(path if path else "URL")
        except: labels.append("URL")
    data = [item['2xx'] for item in top_urls]
    chart_config = {
        "type": "bar",
        "data": {"labels": labels, "datasets": [{"label": "2XX Count", "data": data, "backgroundColor": "#10b981", "borderRadius": 4}]},
        "options": {"plugins": {"title": {"display": True, "text": "2XX Count vs URL", "font": {"size": 14}}, "legend": {"display": False}}, "scales": {"y": {"beginAtZero": True}}}
    }
    encoded_config = urllib.parse.quote(json.dumps(chart_config))
    url = f"https://quickchart.io/chart?w=400&h=300&c={encoded_config}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'AWS-Lambda-Report'})
        with urllib.request.urlopen(req, timeout=10) as response: return response.read()
    except Exception: return None
