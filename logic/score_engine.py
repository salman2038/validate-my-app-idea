def calculate_complexity(features, integrations):
    """Simple weighted complexity scoring."""
    feature_count = len(features.split(", ")) if features else 0
    integration_count = len(integrations.split(", ")) if integrations else 0
    return (feature_count * 1) + (integration_count * 3)


def calculate_financial_viability(arpu, users, opex):
    """Estimate profitability potential (0–100)."""
    try:
        arpu = float(arpu)
        users = float(users)
        opex = float(opex)
        profit_estimate = (arpu * users) - (3 * opex)
        score = max(0, min(100, profit_estimate / 3000))
        return round(score, 2)
    except Exception:
        return 0.0
