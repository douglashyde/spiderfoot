"""PhoneInfoga - phone number OSINT using phonenumbers library."""
import json
import phonenumbers
from phonenumbers import geocoder, carrier, timezone as pn_timezone
from .base import ToolWrapper, Finding, FindingType


class PhoneInfogaTool(ToolWrapper):
    name = "phoneinfoga"
    description = "Advanced phone number OSINT - carrier, location, timezone, validity"
    accepts_input = ["phone"]
    category = "phone_osint"
    pip_module = "phonenumbers"

    def is_available(self):
        try:
            import phonenumbers
            return True
        except ImportError:
            return False

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        number = input_value.strip()

        # Ensure number starts with +
        if not number.startswith("+"):
            # Try common formats
            if number.startswith("1") and len(number) == 11:
                number = "+" + number
            elif len(number) == 10:
                number = "+1" + number
            else:
                number = "+" + number

        try:
            parsed = phonenumbers.parse(number, None)
        except phonenumbers.NumberParseException:
            # Try with US country code as fallback
            try:
                parsed = phonenumbers.parse(input_value.strip(), "US")
            except phonenumbers.NumberParseException as e:
                tool_run.raw_output = f"Could not parse phone number: {e}"
                return findings

        info = {
            "input": input_value,
            "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "country_code": str(parsed.country_code),
            "national_number": str(parsed.national_number),
            "is_valid": phonenumbers.is_valid_number(parsed),
            "is_possible": phonenumbers.is_possible_number(parsed),
            "number_type": _number_type_str(phonenumbers.number_type(parsed)),
        }

        # Location / geocoding
        location = geocoder.description_for_number(parsed, "en")
        if location:
            info["location"] = location

        # Carrier
        carrier_name = carrier.name_for_number(parsed, "en")
        if carrier_name:
            info["carrier"] = carrier_name

        # Timezone
        tz_list = pn_timezone.time_zones_for_number(parsed)
        if tz_list:
            info["timezones"] = list(tz_list)

        # Region code
        region = phonenumbers.region_code_for_number(parsed)
        if region:
            info["region"] = region

        raw_lines = []
        for k, v in info.items():
            raw_lines.append(f"{k}: {v}")
        tool_run.raw_output = "\n".join(raw_lines)

        # Main finding with all info
        findings.append(Finding(
            FindingType.RAW,
            json.dumps(info, default=str),
            source_tool=self.name,
            confidence=0.95,
            metadata={"phone": input_value, "type": "phone_info", **{k: str(v) for k, v in info.items()}},
        ))

        # Location finding
        if info.get("location"):
            findings.append(Finding(
                FindingType.LOCATION,
                info["location"],
                source_tool=self.name,
                confidence=0.85,
                metadata={"phone": input_value, "detail": "location"},
            ))

        # Carrier finding
        if info.get("carrier"):
            findings.append(Finding(
                FindingType.RAW,
                f"Carrier: {info['carrier']}",
                source_tool=self.name,
                confidence=0.85,
                metadata={"phone": input_value, "detail": "carrier"},
            ))

        # Validity warning
        if not info["is_valid"]:
            findings.append(Finding(
                FindingType.RAW,
                f"Phone number {input_value} may not be valid",
                source_tool=self.name,
                confidence=0.7,
                metadata={"phone": input_value, "detail": "validity_warning"},
            ))

        return findings


def _number_type_str(ntype):
    """Convert phonenumbers type constant to human-readable string."""
    type_map = {
        0: "FIXED_LINE",
        1: "MOBILE",
        2: "FIXED_LINE_OR_MOBILE",
        3: "TOLL_FREE",
        4: "PREMIUM_RATE",
        5: "SHARED_COST",
        6: "VOIP",
        7: "PERSONAL_NUMBER",
        8: "PAGER",
        9: "UAN",
        10: "VOICEMAIL",
        99: "UNKNOWN",
    }
    return type_map.get(ntype, "UNKNOWN")
