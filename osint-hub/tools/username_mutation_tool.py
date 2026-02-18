"""Username Mutation Engine - generate sophisticated username permutations."""
import re
import itertools
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


# Leetspeak substitutions
LEET_MAP = {
    'a': ['4', '@'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7'],
    'l': ['1'],
    'g': ['9'],
    'b': ['8'],
}

# Common birth year suffixes
BIRTH_YEARS = [str(y) for y in range(85, 100)] + [str(y) for y in range(0, 10)] + [
    str(y) for y in range(1985, 2005)
]

# Common number suffixes
NUMBER_SUFFIXES = [
    "1", "2", "3", "11", "12", "13", "21", "22", "23",
    "69", "77", "88", "99", "100", "101", "123", "007", "666", "420",
    "x", "xx", "xo", "xoxo",
]

# Common prefixes
PREFIXES = [
    "the", "real", "its", "im", "mr", "ms", "dr", "sir",
    "not", "iamthe", "official", "xo", "x",
]

# Common suffixes
SUFFIXES = [
    "official", "real", "irl", "the", "hq",
    "dev", "tech", "code", "hack", "sec",
]


class UsernameMutationTool(ToolWrapper):
    name = "username_mutation"
    description = "Advanced username permutation engine - generates leetspeak, birth years, cultural variants, and platform-specific mutations"
    accepts_input = ["username", "full_name", "email"]
    category = "username_search"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        base_usernames = set()

        if input_type == "username":
            base_usernames.add(input_value.lower())
        elif input_type == "email" and "@" in input_value:
            local = input_value.split("@")[0].lower()
            base_usernames.add(local)
            # Strip trailing numbers
            stripped = re.sub(r'\d+$', '', local)
            if stripped and stripped != local:
                base_usernames.add(stripped)
        elif input_type == "full_name":
            parts = input_value.lower().split()
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                # Common name-based username patterns
                base_usernames.update([
                    f"{first}{last}",
                    f"{first}.{last}",
                    f"{first}_{last}",
                    f"{first}-{last}",
                    f"{first[0]}{last}",
                    f"{first}{last[0]}",
                    f"{first[0]}.{last}",
                    f"{first}{last[0:3]}",
                    f"{last}{first}",
                    f"{last}.{first}",
                    f"{last}_{first}",
                    f"{last}{first[0]}",
                ])

        tool_run.raw_output += f"Base usernames: {base_usernames}\n"

        all_mutations = set()
        for base in base_usernames:
            mutations = self._generate_all_mutations(base)
            all_mutations.update(mutations)

        # Remove the original input
        all_mutations.discard(input_value.lower())
        for base in base_usernames:
            all_mutations.discard(base)

        tool_run.raw_output += f"Generated {len(all_mutations)} unique mutations\n"

        # Score mutations by likelihood
        scored = self._score_mutations(all_mutations, base_usernames)

        # Return top mutations as findings
        for username, score in scored[:100]:  # Top 100
            findings.append(Finding(
                FindingType.RELATED_USERNAME,
                username,
                source_tool=self.name,
                confidence=min(0.55, score),
                metadata={
                    "generated": True,
                    "mutation_of": list(base_usernames),
                    "mutation_score": round(score, 3),
                    "needs_verification": True,
                },
            ))

        return findings

    def _generate_all_mutations(self, username):
        """Generate all possible mutations of a username."""
        mutations = set()

        # 1. Separator variants
        mutations.update(self._separator_variants(username))

        # 2. Number suffix variants
        mutations.update(self._number_variants(username))

        # 3. Prefix variants
        mutations.update(self._prefix_variants(username))

        # 4. Suffix variants
        mutations.update(self._suffix_variants(username))

        # 5. Leetspeak variants (limited to avoid explosion)
        mutations.update(self._leet_variants(username))

        # 6. Truncation variants
        mutations.update(self._truncation_variants(username))

        # 7. Doubling/repetition variants
        mutations.update(self._repetition_variants(username))

        # 8. Case variants for display names
        mutations.update(self._case_variants(username))

        # Filter out invalid usernames
        valid = set()
        for m in mutations:
            m = m.strip()
            if m and len(m) >= 3 and len(m) <= 30 and m != username:
                # Most platforms allow alphanumeric, dots, underscores, hyphens
                if re.match(r'^[a-zA-Z0-9._\-]+$', m):
                    valid.add(m)

        return valid

    def _separator_variants(self, username):
        """Generate separator variants: johndoe → john.doe, john_doe, etc."""
        variants = set()
        separators = ['.', '_', '-', '']

        # If has separator, try all others
        for old_sep in separators:
            if old_sep and old_sep in username:
                parts = username.split(old_sep)
                for new_sep in separators:
                    variant = new_sep.join(parts)
                    variants.add(variant)

        # Try splitting camelCase
        words = re.findall(r'[a-z]+', username.lower())
        if len(words) >= 2 and ''.join(words) == username.lower():
            for sep in separators:
                variants.add(sep.join(words))

        return variants

    def _number_variants(self, username):
        """Add common number suffixes."""
        variants = set()
        # Strip existing trailing numbers
        base = re.sub(r'\d+$', '', username)
        if not base:
            return variants

        for suffix in NUMBER_SUFFIXES:
            variants.add(f"{base}{suffix}")

        # Birth year suffixes
        for year in BIRTH_YEARS:
            variants.add(f"{base}{year}")

        # If has trailing numbers, try without
        if base != username:
            variants.add(base)

        return variants

    def _prefix_variants(self, username):
        """Add common prefixes."""
        variants = set()
        for prefix in PREFIXES:
            variants.add(f"{prefix}{username}")
            variants.add(f"{prefix}_{username}")
            variants.add(f"{prefix}.{username}")
        return variants

    def _suffix_variants(self, username):
        """Add common suffixes."""
        variants = set()
        base = re.sub(r'\d+$', '', username)
        for suffix in SUFFIXES:
            variants.add(f"{base}{suffix}")
            variants.add(f"{base}_{suffix}")
            variants.add(f"{base}.{suffix}")
        return variants

    def _leet_variants(self, username):
        """Generate leetspeak variants (limited)."""
        variants = set()
        lower = username.lower()

        # Single character substitutions only (to avoid combinatorial explosion)
        for i, char in enumerate(lower):
            if char in LEET_MAP:
                for replacement in LEET_MAP[char]:
                    variant = lower[:i] + replacement + lower[i+1:]
                    variants.add(variant)

        # Full leet (one pass)
        full_leet = lower
        for char, replacements in LEET_MAP.items():
            full_leet = full_leet.replace(char, replacements[0], 1)
        if full_leet != lower:
            variants.add(full_leet)

        return variants

    def _truncation_variants(self, username):
        """Generate truncated variants."""
        variants = set()
        if len(username) >= 6:
            # First N characters
            for n in [4, 5, 6, 8]:
                if n < len(username):
                    variants.add(username[:n])

            # Last N characters
            for n in [4, 5, 6]:
                if n < len(username):
                    variants.add(username[-n:])

        return variants

    def _repetition_variants(self, username):
        """Generate doubling/repetition variants."""
        variants = set()
        # Double last letter
        if username and username[-1].isalpha():
            variants.add(username + username[-1])

        # xx suffix
        variants.add(username + "x")
        variants.add(username + "xx")

        return variants

    def _case_variants(self, username):
        """Generate case variants."""
        variants = set()
        variants.add(username.lower())
        variants.add(username.upper())
        variants.add(username.capitalize())

        # CamelCase if has separator
        for sep in ['.', '_', '-']:
            if sep in username:
                parts = username.split(sep)
                variants.add(''.join(p.capitalize() for p in parts))

        return variants

    def _score_mutations(self, mutations, base_usernames):
        """Score mutations by likelihood of being the actual username."""
        scored = []
        for mutation in mutations:
            score = 0.3  # base score

            for base in base_usernames:
                # Closer to original = higher score
                if len(mutation) == len(base):
                    score += 0.1
                if mutation.startswith(base[:3]):
                    score += 0.05
                if mutation.endswith(base[-3:]):
                    score += 0.05

                # Simple variants are more likely
                diff = abs(len(mutation) - len(base))
                if diff <= 2:
                    score += 0.05
                if diff <= 4:
                    score += 0.02

            # Penalize very long mutations
            if len(mutation) > 20:
                score -= 0.05
            # Penalize very short
            if len(mutation) < 4:
                score -= 0.05

            # Boost if it's a simple separator change
            for base in base_usernames:
                base_clean = re.sub(r'[._\-]', '', base)
                mut_clean = re.sub(r'[._\-]', '', mutation)
                if base_clean == mut_clean:
                    score += 0.15

            scored.append((mutation, min(score, 0.55)))

        scored.sort(key=lambda x: -x[1])
        return scored
