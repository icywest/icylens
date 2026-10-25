from app.schemas.ml_dataset import FeatureExtractionSettings
from app.schemas.ml_features import MLFeatureVector
from app.schemas.static_analysis import StaticAnalysisResponse

INDICATOR_FEATURE_MAP = {
    "network.url_candidate": "has_url_candidate",
    "network.ipv4_candidate": "has_ipv4_candidate",
    "command.powershell_reference": "has_powershell_reference",
    "command.encoded_command_token": "has_encoded_command_token",
    "file.script_reference": "has_script_reference",
}


def extract_ml_features(
    report: StaticAnalysisResponse,
    settings: FeatureExtractionSettings,
) -> MLFeatureVector:
    """Adapt an already-produced static report without reading sample bytes."""
    strings = report.content.strings
    if (
        strings.minimum_length != settings.minimum_string_length
        or strings.maximum_retained_strings != settings.maximum_retained_strings
        or strings.maximum_characters_per_string
        != settings.maximum_characters_per_string
    ):
        raise ValueError("report string settings do not match extraction settings")

    flags = dict.fromkeys(INDICATOR_FEATURE_MAP.values(), False)
    for indicator in report.indicators:
        feature_name = INDICATOR_FEATURE_MAP.get(indicator.id)
        if feature_name is not None:
            flags[feature_name] = True

    return MLFeatureVector(
        file_size_bytes=report.fingerprint.size_bytes,
        shannon_entropy=report.content.entropy.shannon_entropy,
        printable_string_count=strings.observed_count,
        retained_string_count=strings.retained_count,
        indicator_count=len(report.indicators),
        detected_format=report.fingerprint.detected_format,
        format_consistency=report.fingerprint.format_consistency,
        strings_truncated=strings.truncated,
        indicators_truncated=report.indicators_truncated,
        **flags,
    )
