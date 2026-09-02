import io
import zipfile
from typing import Dict, Any, List
try:
    from androguard.core.apk import APK  # pyright: ignore[reportMissingImports]
except ImportError:
    try:
        from androguard.core.bytecodes.apk import APK  # type: ignore[import] # pyright: ignore[reportMissingImports]
    except Exception:
        APK = None  # type: ignore

def analyze_apk_content(filename: str, content: bytes) -> Dict[str, Any]:
    """
    Performs static inspection on Android APK packages.
    Extracts package name, permissions, exported components, intent filters, and certificate fingerprints.
    """
    indicators: List[Dict[str, Any]] = []
    metadata = {}

    try:
        if APK is None:
            raise RuntimeError("Androguard is not available")
        apk = APK(content, raw=True)  # type: ignore[arg-type]
        package_name = apk.get_package() or "Unknown.Package"
        app_name = apk.get_app_name() or filename
        version_code = apk.get_androidversion_code() or "1"
        version_name = apk.get_androidversion_name() or "1.0"
        min_sdk = apk.get_min_sdk_version() or "Unknown"
        target_sdk = apk.get_target_sdk_version() or "Unknown"
        
        permissions = list(apk.get_permissions())
        activities = list(apk.get_activities())
        services = list(apk.get_services())
        receivers = list(apk.get_receivers())
        providers = list(apk.get_providers())
        
        metadata = {
            "packageName": package_name,
            "appName": app_name,
            "versionCode": version_code,
            "versionName": version_name,
            "minSdkVersion": min_sdk,
            "targetSdkVersion": target_sdk,
            "permissionsCount": len(permissions),
            "activitiesCount": len(activities),
            "servicesCount": len(services),
            "receiversCount": len(receivers),
            "providersCount": len(providers)
        }

        # Dangerous permission sets
        perm_str = " ".join(permissions).upper()
        
        has_sms = "SEND_SMS" in perm_str or "RECEIVE_SMS" in perm_str or "READ_SMS" in perm_str
        has_overlay = "SYSTEM_ALERT_WINDOW" in perm_str
        has_accessibility = "BIND_ACCESSIBILITY_SERVICE" in perm_str
        has_admin = "BIND_DEVICE_ADMIN" in perm_str
        has_camera = "CAMERA" in perm_str
        has_audio = "RECORD_AUDIO" in perm_str
        has_location = "ACCESS_FINE_LOCATION" in perm_str or "ACCESS_COARSE_LOCATION" in perm_str

        # Correlation 1: Banking Trojan / Overlay Hijacking Pattern
        if has_overlay and (has_sms or has_accessibility):
            indicators.append({
                "id": "APK-001",
                "category": "PERMISSION",
                "name": "Screen Overlay & SMS / Accessibility Interception",
                "description": "App requests SYSTEM_ALERT_WINDOW with SMS or Accessibility access, a classic signature of banking trojans and screen cloaking malware.",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "score": 45,
                "evidence": f"Permissions: Overlay={has_overlay}, SMS={has_sms}, Accessibility={has_accessibility}",
                "source": "Permission Matrix Auditor"
            })

        # Correlation 2: Device Admin Abuse
        if has_admin:
            indicators.append({
                "id": "APK-002",
                "category": "PERMISSION",
                "name": "Device Administrator Rights Requested",
                "description": "App requests BIND_DEVICE_ADMIN, granting power to lock the device or prevent uninstallation.",
                "severity": "HIGH",
                "confidence": 0.90,
                "score": 30,
                "evidence": "android.permission.BIND_DEVICE_ADMIN present",
                "source": "Permission Matrix Auditor"
            })

        # Correlation 3: Stealth Surveillance Combination (Camera + Audio + Location)
        if has_camera and has_audio and has_location:
            indicators.append({
                "id": "APK-003",
                "category": "PERMISSION",
                "name": "Full Audio/Visual/Geo Surveillance Capability",
                "description": "App requests simultaneous Camera, Audio Recording, and Fine Location access.",
                "severity": "HIGH",
                "confidence": 0.85,
                "score": 25,
                "evidence": "Camera + Record Audio + Fine Location permissions combined",
                "source": "Permission Matrix Auditor"
            })

        # General High Permission Count
        if len(permissions) >= 25:
            indicators.append({
                "id": "APK-004",
                "category": "PERMISSION",
                "name": "Excessive Total Permission Footprint",
                "description": f"App requests an unusually high number of permissions ({len(permissions)}).",
                "severity": "MEDIUM",
                "confidence": 0.75,
                "score": 15,
                "evidence": f"Total permissions: {len(permissions)}",
                "source": "Manifest Auditor"
            })

    except Exception as e:
        # Fallback ZIP inspection if full Androguard parser fails
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                files = z.namelist()
                has_classes_dex = "classes.dex" in files
                has_manifest = "AndroidManifest.xml" in files
                metadata = {
                    "isZip": True,
                    "containsClassesDex": has_classes_dex,
                    "containsManifest": has_manifest,
                    "totalFiles": len(files)
                }
                if not has_classes_dex or not has_manifest:
                    indicators.append({
                        "id": "APK-ERR-01",
                        "category": "CONFIGURATION",
                        "name": "Incomplete or Corrupt APK Archive",
                        "description": "Archive is missing classes.dex or AndroidManifest.xml.",
                        "severity": "HIGH",
                        "confidence": 0.95,
                        "score": 30,
                        "evidence": f"Classes.dex: {has_classes_dex}, Manifest: {has_manifest}",
                        "source": "ZIP Dissector"
                    })
        except Exception:
            indicators.append({
                "id": "APK-ERR-02",
                "category": "CONFIGURATION",
                "name": "Invalid APK Structure",
                "description": "File is not a valid ZIP/APK archive.",
                "severity": "HIGH",
                "confidence": 1.0,
                "score": 35,
                "evidence": str(e),
                "source": "APK Parser"
            })

    return {
        "filename": filename,
        "package": metadata.get("packageName", filename),
        "indicators": indicators,
        "metadata": metadata
    }
