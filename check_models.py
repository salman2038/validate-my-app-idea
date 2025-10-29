import urllib.request, json

API_KEY = "AIzaSyAf9VMQB-LwiML4aYt2MIsGHXLGXa_dlZk"  # paste your key here

url = f"https://generativelanguage.googleapis.com/v1beta/models?key={API_KEY}"
with urllib.request.urlopen(url) as response:
    data = json.loads(response.read().decode("utf-8"))
    for m in data.get("models", []):
        print(m["name"])
