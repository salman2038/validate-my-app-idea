from logic.gemini_api import call_gemini

test_data = {
    "core_problem_statement": "Help students manage study time.",
    "user_role_segment": "University students",
    "monetization_model": "Free with ads",
    "unique_value_proposition": "AI-based time tracking",
    "primary_competitors_text": "Todoist, Notion",
    "must_have_features_list": "Reminders, Analytics, Reports",
    "arpu_estimate_usd": "2",
    "acquisition_goal_3mo": "200",
    "monthly_opex_est_usd": "500",
    "external_integrations_list": "Google Calendar",
    "client_post_launch_fear": "Low engagement",
    "client_critical_question": "How to retain users long-term?"
}

print(call_gemini(test_data))