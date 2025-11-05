import os
import json
import re
import time
from dotenv import load_dotenv
import google.genai as genai

# Load environment variables
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError("❌ GEMINI_API_KEY not found in .env file")

# Initialize Gemini client
client = genai.Client(api_key=api_key)

# Model fallback priority
MODEL_PRIORITY = [
    "models/gemini-2.0-flash",
    "models/gemini-1.5-pro",
    "models/gemini-1.5-flash"
]


def make_prompt(user_inputs):
    """Generate a detailed evaluation prompt for AI."""
    return (
        "You are an expert startup analyst. Evaluate the following mobile app idea:\n\n"
        f"Problem: {user_inputs.get('core_problem_statement')}\n"
        f"Target Users: {user_inputs.get('user_role_segment')}\n"
        f"Monetization: {user_inputs.get('monetization_model')}\n"
        f"Unique Value: {user_inputs.get('unique_value_proposition')}\n"
        f"Competitors: {user_inputs.get('primary_competitors_text')}\n"
        f"Features: {user_inputs.get('must_have_features_list')}\n"
        f"ARPU: {user_inputs.get('arpu_estimate_usd')}\n"
        f"Users in 3 months: {user_inputs.get('acquisition_goal_3mo')}\n"
        f"OPEX: {user_inputs.get('monthly_opex_est_usd')}\n"
        f"Integrations: {user_inputs.get('external_integrations_list')}\n"
        f"Post-launch fear: {user_inputs.get('client_post_launch_fear')}\n"
        f"Critical question: {user_inputs.get('client_critical_question')}\n\n"
        "Return ONLY a JSON object in this format:\n"
        "{\n"
        "  \"ai_score\": number (0-100),\n"
        "  \"verdict\": \"Go\" or \"Needs Improvement\" or \"Not Recommended\",\n"
        "  \"suggestions\": [\"High-level actionable suggestions...\"],\n"
        "  \"summary\": {\n"
        "      \"overview\": \"Brief summary.\",\n"
        "      \"strengths\": [\"Strengths list\"],\n"
        "      \"weaknesses\": [\"Weaknesses list\"],\n"
        "      \"recommendations\": [\"Recommendations list\"]\n"
        "  }\n"
        "}"
    )


def call_gemini(user_inputs):
    """Robust AI call with retry, fallback, and structured output."""
    prompt = make_prompt(user_inputs)
    text_output = ""
    parsed = None

    for model_name in MODEL_PRIORITY:
        try:
            print(f"🧠 Trying model: {model_name}")
            response = client.models.generate_content(
                model=model_name,
                contents=prompt
            )

            text_output = response.candidates[0].content.parts[0].text.strip()
            json_match = re.search(r"\{[\s\S]*\}", text_output)

            if json_match:
                parsed = json.loads(json_match.group(0), strict=False)
                print(f"✅ Model succeeded: {model_name}")
                break  # Success → exit the loop
            else:
                print(f"⚠️ Model {model_name} did not return valid JSON.")
        except Exception as e:
            print(f"❌ Error with {model_name}: {e}")
            time.sleep(1)  # wait before trying next model
            continue

    # If all models failed
    if not parsed:
        print("❌ All Gemini models failed — returning safe fallback response.")
        return {
            "ai_score": 0,
            "verdict": "Error",
            "suggestions": ["AI service temporarily unavailable. Please try again later."],
            "summary": {
                "overview": "Evaluation skipped due to API unavailability.",
                "strengths": [],
                "weaknesses": [],
                "recommendations": [],
                "scorecard": {
                    "Innovation": 0,
                    "Market Potential": 0,
                    "Technical Complexity": 0,
                    "Financial Viability": 0,
                    "User Experience": 0
                },
                "swot": {
                    "Strengths": [],
                    "Weaknesses": [],
                    "Opportunities": [],
                    "Threats": []
                }
            }
        }

    # --- Ensure structured keys exist (for result.html) ---
    parsed.setdefault("ai_score", 0)
    parsed.setdefault("verdict", "Unknown")
    parsed.setdefault("suggestions", [])
    parsed.setdefault("summary", {})

    summary = parsed["summary"]
    summary.setdefault("overview", "No overview available.")
    summary.setdefault("strengths", [])
    summary.setdefault("weaknesses", [])
    summary.setdefault("recommendations", [])
    summary.setdefault("scorecard", {
        "Innovation": 7,
        "Market Potential": 7,
        "Technical Complexity": 6,
        "Financial Viability": 7,
        "User Experience": 8
    })
    summary.setdefault("swot", {
        "Strengths": summary.get("strengths", []),
        "Weaknesses": summary.get("weaknesses", []),
        "Opportunities": ["Potential market growth", "Scalable tech stack"],
        "Threats": ["Competition", "Funding limitations"]
    })

    return parsed