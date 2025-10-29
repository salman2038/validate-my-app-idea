import os
from dotenv import load_dotenv
import google.genai as genai

# Load environment variables
load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError("❌ GEMINI_API_KEY not found in .env file")

print("✅ GEMINI_API_KEY loaded:", api_key[:8], "********")

# ✅ Create Gemini client properly for google-genai>=1.40
client = genai.Client(api_key=api_key)

# ✅ Use the correct call for content generation
prompt = "Give a one-line startup idea analysis example."
response = client.models.generate_content(
    model="models/gemini-2.5-flash",
    contents=prompt
)

print("\n✅ Gemini Response:")
print(response.candidates[0].content.parts[0].text)