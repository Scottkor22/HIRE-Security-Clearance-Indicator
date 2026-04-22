# Hire Security Clearance Indicator

A TamperMonkey userscript that automatically detects and displays security clearance and citizenship badges on hire.amazon.com candidate profiles.

## Quick Install

1. Install [TamperMonkey](https://www.tampermonkey.net/) for Chrome
2. [Click here to install the script](https://raw.githubusercontent.com/scottkor22/HIRE-Security-Clearance-Indicator/main/hire-security-clearance-indicator.user.js) — TamperMonkey will prompt to install
3. Navigate to hire.amazon.com — badges appear automatically

Or view the [User Guide](https://scottkor22.github.io/HIRE-Security-Clearance-Indicator/) for detailed documentation.

## Where Badges Appear

| Page | URL Pattern | How Badges Load |
|---|---|---|
| **Applicants Tab** | `/ar` | Auto-scanned via API (screening question answers) |
| **Jobs Tab** | `/reqs/{id}` | Auto-scanned via API + cache |
| **CDP** | `/person/{id}` | Cache, notes, JSQ flyout, resume PDF |
| **Sourcing** | `/sourcing/discover` | Cache or resume flyout |
| **Rapid Review** | `/reqs/{id}` flyout | Scanned from flyout screening questions |
| **Recommendations** | `/sourcing/pools/.../recommendations` | Cache only |

## Badge Types and Colors

| Badge | Color | Detected From |
|---|---|---|
| **TS/SCI + L2** | Dark maroon | TS/SCI with Full Scope Polygraph, FSP, Lifestyle Poly |
| **TS/SCI + L1** | Burnt orange | TS/SCI with CI Polygraph, Counter Intelligence Poly |
| **TS/SCI + Poly** | Dark red | TS/SCI with Polygraph (unspecified type) |
| **TS/SCI** | Red | TS/SCI, TS,SCI, Top Secret SCI, Top Secret with Sensitive Compartmented Information |
| **L2** | Dark maroon | L2 Cleared, Level 2 Clearance |
| **L1** | Burnt orange | L1 Cleared, Level 1 Clearance |
| **Interim TS** | Orange | Interim Top Secret, Interim TS |
| **Top Secret** | Orange | Top Secret clearance |
| **DoD Secret** | Gold | DoD Secret clearance, Active/Current Secret clearance |
| **Secret** | Gold | Secret (from screening answer with Answer: prefix) |
| **Public Trust** | Blue | Public Trust |
| **DOE Q** | Purple | DOE Q clearance |
| **Yankee White** | Blue | Yankee White Clearance |
| **US Citizen** | Green | Screening answer: US Citizen, US Citizenship, United States of America |

## Keyword Variations Detected

The script handles many real-world variations found in resumes and screening answers:

- **Separators**: `TS/SCI`, `TS, SCI`, `TS,SCI`
- **Connectors**: `with`, `w/`, `+`
- **Modifiers**: `Active`, `Interim`, `Current` (optional prefix)
- **Poly abbreviations**: `Polygraph`, `Poly` (in compound patterns)
- **Spelled out**: `Top Secret SCI`, `Top Secret Clearance with Sensitive Compartmented Information`
- **PDF artifacts**: Handles split words from PDF text layers (e.g., `F ull Scope` → `Full Scope`)

## Badge Hierarchy

Higher-level badges suppress lower-level ones:

- TS/SCI + L2 → suppresses all below
- TS/SCI → suppresses Top Secret, Secret, DoD Secret, L1, L2, Interim TS
- L2 → suppresses L1
- Top Secret → suppresses Secret

## How Data Is Detected

### Applicants Tab & Jobs Tab (Automatic)
The script queries the `/ar/api/graphql` endpoint for each applicant's screening question answers. Badges appear automatically within seconds. Merges with existing cache to preserve citizenship data.

### CDP — Candidate Detail Page
Multiple detection sources:
- **Notes** — scanned on page load
- **Screening questions (JSQ flyout)** — scanned via 3-second polling when flyout opens
- **Resume PDF (same-origin)** — scanned when resume flyout opens on sourcing page
- **Resume PDF (cross-origin)** — fetched via GM_xmlhttpRequest + pdf.js on CDP

### Sourcing Page
Badges from cache or after opening the resume flyout.

### Rapid Review
Flyout dialog text is scanned for screening question answers.

## Citizenship Detection

US Citizen badges use strict screening-answer-only detection:
- `Answer: US Citizen` or `A. US Citizen`
- `Answer: US Citizenship` or `A. US Citizenship`
- `Answer: United States of America` or `A. United States of America`

If `Answer: Permanent resident` is also detected, the US Citizen badge is suppressed.

## False Positive Prevention

The script strips known false-positive sources before matching:
- Skills tag text (`Security Clearance > Security Clearance SECRET`)
- Screening question body text (only answers trigger badges)
- Questions answered "No" (`I have an active clearance at the TS/SCI level... Answer: No`)
- Diamond/DOD/Topaz eligibility notes
- Own badge text (prevents self-matching)
- Export control question text

## Managing Badges

### Clear a single candidate
Click the **×** button next to any badge to remove it and clear that candidate's cache.

### Clear all badges
Console (F12): `GM_setValue('hsc-clearance-cache', '{}')`

### Cache behavior
- Persists across sessions via TamperMonkey GM storage
- localStorage backup protects against TamperMonkey crashes
- Auto-restores from localStorage if GM storage is empty
- Cache resets automatically on script version changes
- No expiration — badges persist until manually cleared
- Keyed by person ID, UUID, and candidate name for cross-page matching

## SPA Navigation Support

The script detects single-page app navigation via:
- `history.pushState` / `replaceState` interception
- `popstate` event listener
- URL polling (1-second interval)

Badges re-render when navigating between pages without full reloads.

## Installation (Manual)

1. Install [TamperMonkey](https://www.tampermonkey.net/)
2. Open TamperMonkey → Create new script
3. Delete default code
4. Copy contents of `hire-security-clearance-indicator.user.js` and paste
5. Save (Ctrl+S)
6. Navigate to hire.amazon.com

## Updating

1. Copy the latest `.user.js` code
2. Open TamperMonkey → click the script name
3. Select all (Ctrl+A), paste (Ctrl+V), save (Ctrl+S)
4. Cache auto-resets on version change

## Auto-Updates

The script includes `@updateURL` and `@downloadURL` pointing to the GitHub raw file. TamperMonkey checks for updates daily. When a new version is uploaded to GitHub with a bumped `@version` number, all users receive the update automatically within 24 hours.

Users can also manually check: TamperMonkey icon → Dashboard → click the refresh icon next to the script.

## Known Limitations

- Sourcing page badges require opening the resume flyout or having previously visited the CDP
- US Citizenship only detected from screening question answers (not notes or resume)
- Recommendations page shows cached badges only (no API auto-scan)
- Each user builds their own cache — badges are not shared between users
- TamperMonkey crashes can wipe GM storage (localStorage backup mitigates this)

## Dependencies

- [TamperMonkey](https://www.tampermonkey.net/) browser extension
- [pdf.js 3.11.174](https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js) (loaded via @require for cross-origin PDF reading)

## Changelog

### v2.2.0 (Current)
- Added Applicants tab API auto-scan (screening question answers via GraphQL)
- Added Jobs tab API auto-scan
- Added Rapid Review flyout scanning
- Added JDP (Job Detail Page) cached badge display
- Added cross-origin PDF reading on CDP via pdf.js + GM_xmlhttpRequest
- Added "×" clear button on all badges
- Added localStorage backup for cache (survives TamperMonkey crashes)
- Added SPA navigation detection (pushState, popstate, URL polling)
- Added "TS with Full Scope" and "Top Secret SCI" keyword variations
- Added "TS, SCI" (comma separator) and "+" connector support
- Added PDF text normalization for split words (e.g., "F ull Scope" → "Full Scope")
- Added "current" modifier support (e.g., "TS/SCI with current CI polygraph")
- Added Permanent Resident suppression (suppresses US Citizen badge)
- Added screening question "Answer: No" stripping (prevents false positives)
- Removed standalone Polygraph, Clearance, ISSA, ISA patterns (too many false positives)
- Removed skills tag matching (e.g., "Security Clearance > SECRET")
- Strict citizenship detection (screening answers only)
- Fixed scan loop (only re-scans on card count change)
- Fixed badge self-matching (own badge text no longer triggers false positives)
- Cache auto-resets on version change
- GitHub hosting with @updateURL for auto-updates

### v1.0.0 (Initial)
- Basic keyword matching for clearance and citizenship
- Sourcing page card scanning
- Resume PDF scanning (same-origin)
- Badge rendering with color coding
- Filter controls (clearance/citizenship toggles)
- Filter persistence via localStorage
- MutationObserver for dynamic content

## Version

Current: 2.2.0
