from typing import Dict, Any, List

def extract_apk_features(apk_metadata: Dict[str, Any], indicators: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Extracts numerical feature vector for Android APK capability ML analysis.
    """
    permissions = apk_metadata.get("permissions", [])
    dangerous_perms = apk_metadata.get("dangerousPermissions", [])
    exported_activities = apk_metadata.get("exportedActivities", [])
    exported_services = apk_metadata.get("exportedServices", [])
    exported_receivers = apk_metadata.get("exportedReceivers", [])
    
    total_exported = len(exported_activities) + len(exported_services) + len(exported_receivers)
    has_admin = 1.0 if any("BIND_DEVICE_ADMIN" in p for p in permissions) else 0.0
    has_overlay = 1.0 if any("SYSTEM_ALERT_WINDOW" in p for p in permissions) else 0.0
    has_sms = 1.0 if any("SMS" in p for p in permissions) else 0.0
    
    return {
        "permissions_count": float(len(permissions)),
        "dangerous_permissions_count": float(len(dangerous_perms)),
        "exported_components_count": float(total_exported),
        "has_device_admin_intent": has_admin,
        "has_overlay_permission": has_overlay,
        "has_sms_permission": has_sms,
        "overlay_sms_combination": 1.0 if (has_overlay and has_sms) else 0.0,
        "indicators_count": float(len(indicators)),
        "is_debuggable": 1.0 if apk_metadata.get("debuggable") else 0.0,
    }
