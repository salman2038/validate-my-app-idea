import os
from dotenv import load_dotenv
import google.genai as genai
import json
import re

# Load .env
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    # Use standard library logging/error handling
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
        
        # NOTE: Updated the JSON format request for better structure separation
        "Return ONLY a JSON object in this format. Populate all fields with meaningful analysis. Use Markdown lists for suggestions, strengths, weaknesses, and recommendations.\n"
        "{\n"
        "   \"ai_score\": number (0-100),\n"
        "   \"verdict\": \"Go\" or \"Needs Improvement\" or \"Not Recommended\",\n"
        "   \"suggestions\": [\"High-level actionable suggestion 1.\", \"High-level actionable suggestion 2.\"],\n"
        "   \"summary\": {\n"
        "       \"overview\": \"A brief summary of the idea and overall potential.\",\n"
        "       \"strengths\": [\"AI-identified strength 1.\", \"AI-identified strength 2.\"],\n"
        "       \"weaknesses\": [\"AI-identified weakness 1.\", \"AI-identified weakness 2.\"],\n"
        "       \"recommendations\": [\"AI-identified recommendation 1.\"]\n"
        "   }\n"
        "}"
    )


def call_gemini(user_inputs):
    """Send structured data to Gemini and get JSON response safely + append scorecard + SWOT into summary."""
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
                # Use strict=False for better compatibility with slightly non-standard JSON from AI
                parsed = json.loads(json_text, strict=False)
            except json.JSONDecodeError as e:
                # Handle total JSON failure
                return {"error": f"JSON decoding failed from AI response: {e}", "raw_output": text_output}
        else:
            # Handle no JSON found
            return {"error": "AI did not return a valid JSON block.", "raw_output": text_output}
        
        
        # --- CRITICAL FIX: STRUCTURE ADJUSTMENT ---
        
        # Ensure 'summary' exists before trying to update it
        if 'summary' not in parsed or not isinstance(parsed['summary'], dict):
            # If Gemini failed to produce a summary, initialize it
            parsed['summary'] = {}

        # Define the data to append (using the keys your HTML is now looking for)
        # NOTE: I am using 'scorecard' and 'swot' (lowercase) because the HTML is now resilient to this.
        # Ideally, this data would be calculated based on the AI's analysis, but for now, we'll use static placeholders.
        scorecard_data = {
            "Innovation": 8,
            "Market Potential": 7,
            "Technical Complexity": 6,
            "Financial Viability": 7,
            "User Experience": 8
        }

        swot_data = {
            "Strengths": parsed['summary'].get('strengths', []), # Use AI-generated strengths if available
            "Weaknesses": parsed['summary'].get('weaknesses', []), # Use AI-generated weaknesses if available
            "Opportunities": ["Growing demand in target market", "Potential for B2B expansion"],
            "Threats": ["Competition from similar apps", "Changing app store policies"]
        }
        
        # Inject the Scorecard and SWOT data INTO the existing 'summary' dictionary
        # This makes the final structure match the expectations of the Flask route and result.html
        parsed['summary'].update({
            "scorecard": scorecard_data, # Added key
            "swot": swot_data            # Added key
        })
        
        # ⚠️ TEMPORARY DEBUG: Print the structure before returning
        print("--- DEBUG: AI Result Summary ---")
        print(parsed.get('summary'))
        print("---------------------------------")


        return parsed

    except Exception as e:
        print("❌ Gemini API error:", e)
        # Return a structured error response
        return {"ai_score": 0, "verdict": "Error", "suggestions": [f"API call failed: {e}"], "summary": {"error": f"API error: {e}"}}