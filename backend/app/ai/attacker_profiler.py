from __future__ import annotations
from typing import Dict, List, Optional
from datetime import datetime
from app.models import AttackerProfile


CLUSTER_RULES = {
    AttackerProfile.AUTOMATED_BOT: {
        "name": "Automated Bot",
        "description": "Automated scanning or exploitation tool with repetitive patterns",
        "indicators": {
            "high_command_rate": {"weight": 0.25, "threshold": 10, "description": ">10 commands/minute"},
            "low_complexity": {"weight": 0.2, "threshold": 0.3, "description": "Command complexity < 0.3"},
            "repetitive_patterns": {"weight": 0.25, "threshold": 0.8, "description": ">80% repeated commands"},
            "no_adaptation": {"weight": 0.15, "threshold": 0.2, "description": "Low adaptation to responses"},
            "short_session": {"weight": 0.15, "threshold": 30, "description": "Session < 30 seconds"},
        },
    },
    AttackerProfile.SCRIPT_KIDDIE: {
        "name": "Script Kiddie",
        "description": "Uses pre-built tools with limited understanding, follows known attack scripts",
        "indicators": {
            "known_tools": {"weight": 0.3, "threshold": 1, "description": "Uses known offensive tools"},
            "medium_complexity": {"weight": 0.15, "threshold": 0.4, "description": "Command complexity 0.3-0.6"},
            "tutorial_patterns": {"weight": 0.2, "threshold": 0.5, "description": "Follows known tutorial patterns"},
            "some_adaptation": {"weight": 0.15, "threshold": 0.3, "description": "Limited adaptation"},
            "common_targets": {"weight": 0.2, "threshold": 0.7, "description": "Targets common vulnerable services"},
        },
    },
    AttackerProfile.APT: {
        "name": "Advanced Persistent Threat",
        "description": "Sophisticated attacker with custom tools, stealthy techniques, and clear objectives",
        "indicators": {
            "custom_tools": {"weight": 0.2, "threshold": 0.5, "description": "Uses custom or modified tools"},
            "high_complexity": {"weight": 0.2, "threshold": 0.6, "description": "Command complexity > 0.6"},
            "stealth_techniques": {"weight": 0.2, "threshold": 0.3, "description": "Uses obfuscation/stealth"},
            "long_session": {"weight": 0.15, "threshold": 300, "description": "Session > 5 minutes"},
            "multi_stage": {"weight": 0.15, "threshold": 3, "description": "Multiple attack stages detected"},
            "lateral_movement": {"weight": 0.1, "threshold": 0.5, "description": "Attempts lateral movement"},
        },
    },
}


class AttackerProfiler:
    def profile(self, session_analysis: Dict) -> Dict:
        scores = {}

        for profile, config in CLUSTER_RULES.items():
            score = 0.0
            total_weight = 0.0
            details = {}

            for indicator, config_detail in config["indicators"].items():
                weight = config_detail["weight"]
                threshold = config_detail["threshold"]
                total_weight += weight

                value = session_analysis.get(indicator, 0)
                if isinstance(value, bool):
                    indicator_score = 1.0 if value else 0.0
                elif isinstance(value, (int, float)):
                    if threshold > 0:
                        indicator_score = min(value / threshold, 1.0)
                    else:
                        indicator_score = 1.0 if value > 0 else 0.0
                else:
                    indicator_score = 0.0

                score += indicator_score * weight
                details[indicator] = {
                    "value": value,
                    "threshold": threshold,
                    "score": round(indicator_score, 3),
                }

            normalized_score = score / total_weight if total_weight > 0 else 0
            scores[profile.value] = {
                "score": round(normalized_score, 4),
                "details": details,
            }

        dominant_profile = max(scores, key=lambda k: scores[k]["score"])
        dominant_score = scores[dominant_profile]["score"]

        if dominant_score < 0.2:
            dominant_profile = AttackerProfile.UNKNOWN.value
            dominant_score = 0.0

        return {
            "profile": dominant_profile,
            "confidence": round(dominant_score, 4),
            "all_scores": scores,
            "description": CLUSTER_RULES.get(
                AttackerProfile(dominant_profile),
                {"description": "Unknown attacker profile"},
            )["description"] if dominant_profile != AttackerProfile.UNKNOWN.value else "Insufficient data for profiling",
        }

    def profile_from_session(self, session_data: Dict, nlp_results: Dict, ai_results: Dict) -> Dict:
        duration = session_data.get("duration_seconds", 0) or 0
        commands = session_data.get("commands", [])
        command_count = len(commands)
        unique_commands = len(set(commands)) if commands else 0
        command_rate = command_count / max(duration / 60, 0.001)

        repetitive_ratio = 1 - (unique_commands / max(command_count, 1))

        detected_tools = nlp_results.get("tool_names", [])
        complexity = nlp_results.get("complexity_score", 0)
        detected_intents = nlp_results.get("detected_intents", [])

        has_stealth = any(
            i in detected_intents
            for i in ["persistence", "lateral_movement", "data_exfiltration"]
        )
        has_lateral = "lateral_movement" in detected_intents
        multi_stage = len(set(nlp_results.get("categories", []))) >= 3

        analysis = {
            "high_command_rate": command_rate,
            "low_complexity": 1 - complexity,
            "repetitive_patterns": repetitive_ratio,
            "no_adaptation": 1 - (unique_commands / max(command_count, 1)),
            "short_session": 1 if duration < 30 else 0,
            "known_tools": len(detected_tools),
            "medium_complexity": complexity,
            "tutorial_patterns": 0.5 if len(detected_tools) <= 2 else 0,
            "some_adaptation": unique_commands / max(command_count, 1),
            "common_targets": 0.7 if session_data.get("protocol") in ["ssh", "ftp"] else 0.3,
            "custom_tools": 0.5 if any(t not in ["nmap", "hydra", "sqlmap"] for t in detected_tools) else 0,
            "high_complexity": complexity,
            "stealth_techniques": 1.0 if has_stealth else 0,
            "long_session": 1 if duration > 300 else 0,
            "multi_stage": multi_stage,
            "lateral_movement": 1.0 if has_lateral else 0,
        }

        return self.profile(analysis)


attacker_profiler = AttackerProfiler()
