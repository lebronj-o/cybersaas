"""
Module Historique — Sauvegarde et récupération des scans via Supabase
"""
import json
from datetime import datetime
from typing import List, Dict


def save_scan(supabase, user_id: str, company: str, scores: dict, findings: dict) -> bool:
    """Sauvegarde un scan complet dans Supabase."""
    try:
        data = {
            "user_id": user_id,
            "company_name": company,
            "scanned_at": datetime.now().isoformat(),
            "score_global": scores.get("global", 0),
            "score_network": scores.get("network", 0),
            "score_access": scores.get("access", 0),
            "score_compliance": scores.get("compliance", 0),
            "findings": json.dumps(findings),
        }
        supabase.table("scans").insert(data).execute()
        return True
    except Exception as e:
        print(f"Erreur save_scan: {e}")
        return False


def get_scan_history(supabase, user_id: str, limit: int = 10) -> List[Dict]:
    """Récupère l'historique des scans d'un utilisateur."""
    try:
        res = supabase.table("scans") \
            .select("*") \
            .eq("user_id", user_id) \
            .order("scanned_at", desc=True) \
            .limit(limit) \
            .execute()
        return res.data or []
    except Exception as e:
        print(f"Erreur get_scan_history: {e}")
        return []
