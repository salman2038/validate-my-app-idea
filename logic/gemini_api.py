import os
from dotenv import load_dotenv
import google.genai as genai
import json
import re

# Load .env
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError("❌ GEMINI_API_KEY not found in .env")

# Initialize client
client = genai.Client(api_key=api_key)


def make_prompt(user_inputs):
    """Generate a clear AI prompt from form data"""
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
        "  \"suggestions\": [\"...\", \"...\"],\n"
        "  \"summary\": {\n"
        "    \"overview\": \"...\",\n"
        "    \"strengths\": [\"...\"],\n"
        "    \"weaknesses\": [\"...\"],\n"
        "    \"recommendations\": [\"...\"]\n"
        "  }\n"
        "}"
    )


def call_gemini(user_inputs):
    """Send structured data to Gemini and get JSON response safely + append scorecard + SWOT"""
    try:
        prompt = make_prompt(user_inputs)
        response = client.models.generate_content(
            model="models/gemini-2.5-flash",
            contents=prompt
        )

        text_output = response.candidates[0].content.parts[0].text.strip()

        # 🧠 Extract JSON block if Gemini adds text around it
        json_match = re.search(r"\{[\s\S]*\}", text_output)
        if json_match:
            json_text = json_match.group(0)
            try:
                parsed = json.loads(json_text)
            except json.JSONDecodeError:
                parsed = {"raw_output": text_output}
        else:
            parsed = {"raw_output": text_output}

        # ✅ Add derived metrics (scorecard + SWOT)
        scorecard = {
            "Innovation": 8,
            "Market Potential": 7,
            "Technical Complexity": 6,
            "Financial Viability": 7,
            "User Experience": 8
        }

        swot = {
            "Strengths": ["Unique niche", "Strong user pain point"],
            "Weaknesses": ["Limited MVP clarity", "High acquisition cost"],
            "Opportunities": ["Growing demand in target market", "Potential for B2B expansion"],
            "Threats": ["Competition from similar apps", "Changing app store policies"]
        }

        parsed.update({
            "scorecard": scorecard,
            "swot": swot
        })

        return parsed

    except Exception as e:
        print("❌ Gemini API error:", e)
        return {"error": str(e)}