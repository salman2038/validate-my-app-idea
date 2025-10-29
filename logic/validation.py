# logic/validation.py
import re

def validate_app_idea(inputs: dict) -> tuple[bool, str]:
    """
    Checks if the submission looks like a genuine mobile app idea.
    Returns (is_valid, reason)
    """
    text = " ".join(str(v or "") for v in inputs.values()).lower()

    # Too short or meaningless
    if len(text.strip()) < 200:
        return False, "Your idea description is too short. Please add more detail."

    # Detect non-app related content
    app_keywords = ["app", "mobile", "android", "ios", "platform", "software", "application"]
    if not any(k in text for k in app_keywords):
        return False, "Your idea does not seem related to a mobile application."

    # Detect obvious junk
    if re.search(r"\b(test|hello|check|nonsense|abcd|asdf)\b", text):
        return False, "Please provide a meaningful app concept instead of placeholder text."

    return True, ""