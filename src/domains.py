"""
Domain analysis for EmailShield: registrable domain extraction, punycode
decoding, Unicode confusable normalisation, and lookalike scoring.

Three separate problems live here and they are often conflated:

  1. Which part of a hostname is the registrable domain. You cannot compare
     "mail.example.co.uk" to "example.com" without knowing that "co.uk" is a
     public suffix and "example.co.uk" is the registrable unit.

  2. Homoglyphs. A domain can use characters that render almost identically to
     ASCII, for example Cyrillic small a (U+0430) in place of Latin a. These are
     transmitted as punycode (xn--...) and must be decoded and then folded onto
     their ASCII skeleton before any comparison is meaningful.

  3. Typosquats. Ordinary ASCII domains a short edit away from a real one, for
     example "exarnple.com" or "exmaple.com". These need edit distance, and
     ideally a model of which substitutions are actually plausible.

All three need a comparison set. Edit distance against nothing is meaningless.
That set is `protected_domains` and it is a deliberate configuration decision,
not an implementation detail.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
# Public suffix handling
# --------------------------------------------------------------------------- #
#
# The real Public Suffix List has thousands of entries and changes. Bundling a
# stale copy would be worse than being explicit about the subset covered, so this
# is a documented subset that covers the cases in the corpus plus the common UK
# and generic suffixes. `registrable_domain` reports when it has fallen back to
# the naive two-label assumption, and that uncertainty is carried into the signal
# output rather than hidden.

MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk", "police.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "co.za", "co.jp", "or.jp", "ne.jp", "ac.jp",
    "com.br", "com.mx", "com.sg", "com.hk", "com.tr", "com.cn",
    "co.in", "net.in", "org.in",
    "github.io", "pages.dev", "web.app", "firebaseapp.com",
    "s3.amazonaws.com", "blob.core.windows.net",
}

SINGLE_LABEL_SUFFIXES = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "co",
    "uk", "de", "fr", "nl", "es", "it", "se", "no", "dk", "fi", "pl", "ru", "cn",
    "jp", "br", "in", "au", "nz", "za", "ca", "us", "eu", "ie", "ch", "at", "be",
    "app", "dev", "xyz", "top", "site", "online", "shop", "store", "cloud",
    "link", "click", "live", "zip", "mov", "support", "help", "email", "tech",
    # RFC 6761 reserves .example for documentation and testing. Included so that
    # each fictional organisation in the corpus has its own registrable domain
    # rather than all of them collapsing onto example.com.
    "example", "test", "invalid", "localhost",
}


@dataclass
class DomainParts:
    host: str
    subdomains: str
    registrable: str          # e.g. "example.co.uk"
    public_suffix: str        # e.g. "co.uk"
    suffix_known: bool        # False means the two-label fallback was used


def registrable_domain(host: str) -> DomainParts:
    """Split a hostname into subdomains, registrable domain and public suffix."""
    h = host.strip().strip(".").lower()
    labels = h.split(".")

    if len(labels) < 2:
        return DomainParts(h, "", h, "", suffix_known=False)

    for depth in (3, 2):
        if len(labels) >= depth + 1:
            candidate = ".".join(labels[-depth:])
            if candidate in MULTI_LABEL_SUFFIXES:
                return DomainParts(
                    host=h,
                    subdomains=".".join(labels[: -(depth + 1)]),
                    registrable=".".join(labels[-(depth + 1):]),
                    public_suffix=candidate,
                    suffix_known=True,
                )

    tld = labels[-1]
    if tld in SINGLE_LABEL_SUFFIXES:
        return DomainParts(
            host=h,
            subdomains=".".join(labels[:-2]),
            registrable=".".join(labels[-2:]),
            public_suffix=tld,
            suffix_known=True,
        )

    # Unknown suffix. Assume the last two labels are the registrable unit and say
    # so, because this assumption is wrong for suffixes not in the subset above.
    return DomainParts(
        host=h,
        subdomains=".".join(labels[:-2]),
        registrable=".".join(labels[-2:]),
        public_suffix=tld,
        suffix_known=False,
    )


# --------------------------------------------------------------------------- #
# Punycode and confusables
# --------------------------------------------------------------------------- #

# Characters that render close enough to an ASCII character to fool a reader.
# This is a hand-built subset of the Unicode confusables data, covering Cyrillic
# and Greek lookalikes plus the digit and Latin substitutions used in typosquats.
CONFUSABLE_MAP = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u04bb": "h",
    "\u0410": "a", "\u0415": "e", "\u041e": "o", "\u0420": "p", "\u0421": "c",
    "\u0391": "a", "\u0392": "b", "\u0395": "e", "\u0397": "h", "\u0399": "i",
    "\u039a": "k", "\u039c": "m", "\u039d": "n", "\u039f": "o", "\u03a1": "p",
    "\u03a4": "t", "\u03a5": "y", "\u03a7": "x", "\u03b1": "a", "\u03bf": "o",
    "\u03c1": "p", "\u03c5": "v", "\u0131": "i", "\u0261": "g", "\u04cf": "l",
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
    "\uff41": "a", "\uff45": "e", "\uff4f": "o",
}

# Pairs that are visually close in ASCII alone.
ASCII_SHAPE_MAP = {
    "1": "l", "0": "o", "5": "s", "3": "e", "8": "b",
}


def decode_punycode_host(host: str) -> tuple[str, bool]:
    """
    Decode any xn-- labels in a hostname to their Unicode form.

    Returns (decoded_host, contained_punycode).
    """
    labels = host.split(".")
    had_puny = False
    out: list[str] = []
    for label in labels:
        if label.lower().startswith("xn--"):
            had_puny = True
            try:
                out.append(label.encode("ascii").decode("idna"))
            except (UnicodeError, UnicodeDecodeError):
                out.append(label)          # keep the raw label rather than drop it
        else:
            out.append(label)
    return ".".join(out), had_puny


def skeleton(text: str) -> str:
    """
    Reduce a string to a comparison skeleton.

    Strips accents, maps known confusables onto their ASCII lookalike, folds the
    ASCII shape pairs, and lowercases. Two strings with the same skeleton look
    alike to a human even when their bytes differ completely.
    """
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    mapped = "".join(CONFUSABLE_MAP.get(c, c) for c in stripped.lower())
    return "".join(ASCII_SHAPE_MAP.get(c, c) for c in mapped)


def has_mixed_scripts(text: str) -> bool:
    """
    True if the string mixes Unicode scripts in a way legitimate domains rarely do.

    A domain that is entirely Cyrillic is normal for a Russian-language site. A
    domain that is mostly Latin with one Cyrillic character is a homoglyph attack.
    Mixing is the signal, not the presence of non-Latin script.
    """
    scripts: set[str] = set()
    for char in text:
        if not char.isalpha():
            continue
        try:
            name = unicodedata.name(char)
        except ValueError:
            continue
        family = name.split(" ")[0]
        if family in {"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC"}:
            scripts.add(family)
    return len(scripts) > 1


# --------------------------------------------------------------------------- #
# Edit distance
# --------------------------------------------------------------------------- #

# Rows of a QWERTY keyboard, used to decide whether a substitution is a plausible
# typo or an unrelated character. "exanple.com" (n next to m) is a likelier
# genuine typo than "exaqple.com".
_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")


def _adjacent_keys(char: str) -> set[str]:
    out: set[str] = set()
    for row in _KEYBOARD_ROWS:
        idx = row.find(char)
        if idx == -1:
            continue
        if idx > 0:
            out.add(row[idx - 1])
        if idx < len(row) - 1:
            out.add(row[idx + 1])
    return out


def damerau_levenshtein(a: str, b: str) -> int:
    """
    Edit distance allowing insertion, deletion, substitution and transposition.

    Transposition matters for this problem: "exmaple.com" is one swap from
    "example.com" but plain Levenshtein scores it 2, which would push a very
    convincing typosquat below a distance-1 threshold.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev_prev: list[int] = []
    prev = list(range(len(b) + 1))

    for i, ca in enumerate(a, start=1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current[j] = min(
                current[j - 1] + 1,          # insertion
                prev[j] + 1,                 # deletion
                prev[j - 1] + cost,          # substitution
            )
            if (
                i > 1 and j > 1
                and ca == b[j - 2]
                and a[i - 2] == cb
            ):
                current[j] = min(current[j], prev_prev[j - 2] + cost)
        prev_prev = prev
        prev = current

    return prev[len(b)]


@dataclass
class LookalikeMatch:
    candidate: str                 # registrable domain being tested
    protected: str                 # protected domain it resembles
    kind: str                      # "exact_skeleton", "typosquat", "subdomain_spoof"
    distance: int
    plausible_typo: bool           # substitution is keyboard-adjacent
    detail: str


@dataclass
class DomainAssessment:
    host: str
    decoded_host: str
    contained_punycode: bool
    mixed_scripts: bool
    parts: DomainParts
    is_protected: bool
    lookalikes: list[LookalikeMatch] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _substitution_is_plausible(a: str, b: str) -> bool:
    """For two equal-length strings differing in one position, is it a typo?"""
    if len(a) != len(b):
        return False
    diffs = [(x, y) for x, y in zip(a, b) if x != y]
    if len(diffs) != 1:
        return False
    x, y = diffs[0]
    return y in _adjacent_keys(x) or x in _adjacent_keys(y)


def assess_domain(
    host: str,
    protected_domains: set[str],
    max_distance: int = 2,
) -> DomainAssessment:
    """
    Compare one hostname against the protected set.

    protected_domains holds registrable domains, for example {"northgate.co.uk"}.
    Everything is compared at the registrable level, so a subdomain of a
    protected domain is treated as that domain and not as a lookalike of it.
    """
    decoded, had_puny = decode_punycode_host(host)
    parts = registrable_domain(decoded)
    assessment = DomainAssessment(
        host=host,
        decoded_host=decoded,
        contained_punycode=had_puny,
        mixed_scripts=has_mixed_scripts(decoded),
        parts=parts,
        is_protected=parts.registrable in protected_domains,
    )

    if had_puny:
        assessment.notes.append(
            f"hostname used punycode; decodes to '{decoded}'"
        )
    if assessment.mixed_scripts:
        assessment.notes.append(
            "hostname mixes Unicode scripts, which is characteristic of homoglyph abuse"
        )
    if not parts.suffix_known:
        assessment.notes.append(
            f"public suffix '{parts.public_suffix}' is not in the bundled subset; "
            "registrable domain was inferred from the last two labels and may be wrong"
        )

    if assessment.is_protected:
        return assessment

    candidate_reg = parts.registrable
    candidate_skeleton = skeleton(candidate_reg)

    for protected in sorted(protected_domains):
        protected_skeleton = skeleton(protected)

        # Case 1: different bytes, identical skeleton. This is the homoglyph case
        # and it is the strongest form, because there is no plausible innocent
        # explanation for a domain that renders identically to another.
        if candidate_reg != protected and candidate_skeleton == protected_skeleton:
            assessment.lookalikes.append(
                LookalikeMatch(
                    candidate=candidate_reg,
                    protected=protected,
                    kind="exact_skeleton",
                    distance=0,
                    plausible_typo=False,
                    detail=(
                        f"'{candidate_reg}' renders identically to '{protected}' "
                        f"after confusable folding (both reduce to '{candidate_skeleton}')"
                    ),
                )
            )
            continue

        # Case 2: the protected domain appears as a subdomain label of another
        # registrable domain, for example northgate.co.uk.secure-login.net.
        if protected.split(".")[0] in parts.subdomains.split("."):
            assessment.lookalikes.append(
                LookalikeMatch(
                    candidate=candidate_reg,
                    protected=protected,
                    kind="subdomain_spoof",
                    distance=0,
                    plausible_typo=False,
                    detail=(
                        f"'{protected}' appears in the subdomain of '{candidate_reg}'; "
                        "the registrable domain is not the protected one"
                    ),
                )
            )
            continue

        # Case 3: short edit distance on the skeleton.
        distance = damerau_levenshtein(candidate_skeleton, protected_skeleton)
        if 0 < distance <= max_distance:
            assessment.lookalikes.append(
                LookalikeMatch(
                    candidate=candidate_reg,
                    protected=protected,
                    kind="typosquat",
                    distance=distance,
                    plausible_typo=_substitution_is_plausible(
                        candidate_skeleton, protected_skeleton
                    ),
                    detail=(
                        f"'{candidate_reg}' is {distance} edit(s) from '{protected}'"
                    ),
                )
            )

    return assessment
