// ==UserScript==
// @name         Hire Security Clearance Indicator
// @namespace    https://hire.amazon.com
// @version      2.2.0
// @description  Scans hire.amazon.com search results for security clearance and citizenship keywords, injects color-coded badges, and provides filter controls.
// @match        https://hire.amazon.com/*
// @updateURL    https://raw.githubusercontent.com/scottkor22/HIRE-Security-Clearance-Indicator/main/hire-security-clearance-indicator.user.js
// @downloadURL  https://raw.githubusercontent.com/scottkor22/HIRE-Security-Clearance-Indicator/main/hire-security-clearance-indicator.user.js
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_xmlhttpRequest
// @connect      document-service-data-prod.s3.us-west-2.amazonaws.com
// @connect      *.amazonaws.com
// @require      https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js
// ==/UserScript==

(function () {
  'use strict';

  // ── PageDetector ──────────────────────────────────────────────────────
  /**
   * Determines whether the current page is a hire.amazon.com search results page.
   * Checks the hostname and pathname against known search results URL patterns.
   * @returns {boolean}
   */
  function isSearchResultsPage() {
    var loc = window.location;
    if (loc.hostname !== 'hire.amazon.com') {
      return false;
    }
    return /\/(search|sourcing\/(pools|discover))(\/|$|\?)/.test(loc.pathname);
  }

  // ── KeywordMatcher ─────────────────────────────────────────────────
  /**
   * Clearance patterns ordered from most specific to least specific.
   * All use word boundaries (\b) and case-insensitive flag (i).
   */
  var CLEARANCE_PATTERNS = [
    { label: 'TS/SCI with Full Scope Polygraph', regex: /\b(?:active|interim|current)?\s*TS[\/,]\s*SCI\s*(?:with|w\/|\+)\s*(?:current\s+|active\s+)?(?:full\s*scope\s*)?(?:poly(?:graph)?|lifestyle|FSP)\b/i },
    { label: 'TS/SCI with Full Scope Polygraph', regex: /\bTop\s+Secret\s+SCI\s+(?:with|w\/)\s+(?:current\s+|active\s+)?(?:full\s+scope\s+)?(?:poly(?:graph)?|FSP)\b/i },
    { label: 'TS/SCI with Full Scope Polygraph', regex: /\b(?:active|interim|current)?\s*TS\s+(?:with|w\/|\+)\s+full\s+scope\b/i },
    { label: 'TS/SCI with CI Polygraph', regex: /\b(?:active|interim|current)?\s*TS[\/,]\s*SCI\s*(?:with|w\/|\+)\s*(?:current\s+|active\s+)?(?:CI\s+Poly(?:graph)?|counter\s+intelligence\s+poly(?:graph)?)\b/i },
    { label: 'TS/SCI with CI Polygraph', regex: /\bTop\s+Secret\s+SCI\s+(?:with|w\/)\s+(?:current\s+|active\s+)?CI\s+Poly(?:graph)?\b/i },
    { label: 'TS/SCI with Polygraph', regex: /\b(?:active|interim|current)?\s*TS[\/,]\s*SCI\s*(?:with|w\/|\+)\s*(?:current\s+|active\s+)?(?:Poly(?:graph)?)\b/i },
    { label: 'TS/SCI',               regex: /\b(?:active|interim|current)?\s*TS[\/,]\s*SCI\b|\bTop\s+Secret\s+SCI\b|\bTop\s+Secret\s+(?:Clearance\s+)?(?:with\s+)?Sensitive\s+Compartmented\s+Information/i },
    { label: 'L2 Cleared',           regex: /\b(?:L2|Level\s+2)\s+(?:Cleared?|Clearance)\b/i },
    { label: 'L1 Cleared',           regex: /\b(?:L1|Level\s+1)\s+(?:Cleared?|Clearance)\b/i },
    { label: 'Interim TS',           regex: /\binterim\s+(?:top\s+secret|TS)\b/i },
    { label: 'Top Secret',           regex: /\b(?:active|interim|current)?\s*Top\s+Secret\b/i },
    { label: 'Yankee White Clearance', regex: /\b(?:active|current)?\s*Yankee\s+White\s+Clearance\b/i },
    { label: 'DoD Secret',           regex: /\b(?:active|interim|current)?\s*(?:DoD\s+)?Secret\s+(?:security\s+)?clearance\b/i },
    { label: 'Public Trust',         regex: /\bPublic\s+Trust\b/i },
    { label: 'DOE Q',                regex: /\b(?:active|current)?\s*DOE\s+Q\b/i },
    { label: 'Secret',               regex: /(?:Answer\s*:\s*|A\.\s*)(?:active\s+|interim\s+|current\s+|DoD\s+)?Secret\b|(?:active|interim|current|DoD)\s+Secret\b|\bSecret\s+(?:security\s+)?clearance\b/i },
  ];

  /**
   * Citizenship patterns ordered from most specific to least specific.
   */
  var CITIZENSHIP_PATTERNS = [
    { label: 'US Citizenship', regex: /(?:Answer\s*:|A\.)\s*US\s+Citizenship\b/i },
    { label: 'US Citizen',     regex: /(?:Answer\s*:|A\.)\s*US\s+Citizen\b/i },
    { label: 'United States of America', regex: /(?:Answer\s*:|A\.)\s*United\s+States\s+of\s+America\b/i },
    { label: 'US Citizen',     regex: /United\s+States\s+Citizenship/i },
  ];

  /**
   * Runs all clearance and citizenship patterns against the input text.
   * Returns a MatchResult with deduplicated clearances, hasCitizenship flag,
   * and the first matched citizenshipKeyword.
   * @param {string} text
   * @returns {{ clearances: string[], hasCitizenship: boolean, citizenshipKeyword: string|null }}
   */
  function match(text) {
    var clearances = [];
    var hasCitizenship = false;
    var citizenshipKeyword = null;

    if (typeof text !== 'string' || text.length === 0) {
      return { clearances: clearances, hasCitizenship: hasCitizenship, citizenshipKeyword: citizenshipKeyword };
    }

    // Strip out false-positive phrases before matching
    // Normalize whitespace (PDF text layers often split words across spans)
    var cleanText = text
      .replace(/\s+/g, ' ')
      // Fix common PDF word splits for clearance terms
      .replace(/F\s+ull/gi, 'Full')
      .replace(/S\s+cope/gi, 'Scope')
      .replace(/P\s+oly/gi, 'Poly')
      .replace(/C\s+learance/gi, 'Clearance')
      .replace(/S\s+ecret/gi, 'Secret')
      .replace(/C\s+ompartmented/gi, 'Compartmented')
      .replace(/S\s+ensitive/gi, 'Sensitive')
      .replace(/C\s+itizen/gi, 'Citizen')
      // Strip "I have an active clearance at X level" questions answered "No"
      .replace(/I have an active US government security clearance at the[\s\S]{0,100}?level[\s\S]{0,50}?Answer:\s*No/gi, '')
      .replace(/I have an active US government security clearance at the[\s\S]{0,100}?level[\s\S]{0,50}?A\.\s*No/gi, '')
      // Remove our own badge text concatenated with page chrome
      .replace(/(?:TS\/SCI \+ L2|TS\/SCI \+ L1|TS\/SCI \+ Poly|TS\/SCI|Interim TS|Top Secret|DoD Secret|Public Trust|Yankee White|DOE Q|L1|L2|Secret|US Citizen)(?=\w|Open|Page|ID|Hide|Show)/g, ' ')
      // Diamond/DOD/Topaz eligibility notes
      .replace(/(?:Diamond|DOD|Topaz):\s*Candidate\s+appears\s+eligible\s+for\s+[^.]{0,100}/gi, '')
      .replace(/eligible\s+for\s+Level\s+(?:I|II|1|2)\s+initial\s+only/gi, '')
      .replace(/eligible\s+for\s+(?:initial\s+only|Dual\s+Track\s+processing\s+type)/gi, '')
      // Strip known false-positive phrases
      .replace(/Security\s+Clearance\s*>\s*Security\s+Clearance\s+\w+/gi, '')
      .replace(/background\s+investigation\s+and\s+polygraph\s+examination/gi, '')
      .replace(/Security Check/g, '')
      .replace(/Rehire [Ee]ligibility[^.]{0,100}/g, '')
      .replace(/Profile Exclusion Security Check[^.]{0,100}/gi, '');

    // Track which labels we've already added to avoid duplicates
    var seen = {};

    for (var i = 0; i < CLEARANCE_PATTERNS.length; i++) {
      var pattern = CLEARANCE_PATTERNS[i];
      if (pattern.regex.test(cleanText) && !seen[pattern.label]) {
        // For compound patterns, also mark their sub-patterns as seen
        // e.g. "TS/SCI with Polygraph" should suppress standalone "TS/SCI" and "Polygraph"
        if (pattern.label === 'TS/SCI with Full Scope Polygraph') {
          seen['TS/SCI with CI Polygraph'] = true;
          seen['TS/SCI with Polygraph'] = true;
          seen['TS/SCI'] = true;
          seen['Full Scope Polygraph'] = true;
          seen['CI Polygraph'] = true;
          seen['Polygraph'] = true;
          seen['ISSA'] = true;
          seen['ISA'] = true;
          seen['Clearance'] = true;
          seen['Secret'] = true;
          seen['Top Secret'] = true;
          seen['Interim TS'] = true;
          seen['DoD Secret'] = true;
          seen['L2 Cleared'] = true;
          seen['L1 Cleared'] = true;
        }
        if (pattern.label === 'TS/SCI with CI Polygraph') {
          seen['TS/SCI with Polygraph'] = true;
          seen['TS/SCI'] = true;
          seen['CI Polygraph'] = true;
          seen['Polygraph'] = true;
          seen['ISSA'] = true;
          seen['ISA'] = true;
          seen['Secret'] = true;
          seen['Top Secret'] = true;
          seen['Interim TS'] = true;
          seen['L1 Cleared'] = true;
        }
        if (pattern.label === 'TS/SCI with Polygraph') {
          seen['TS/SCI'] = true;
          seen['Polygraph'] = true;
          seen['ISSA'] = true;
          seen['ISA'] = true;
          seen['Secret'] = true;
          seen['Top Secret'] = true;
          seen['Interim TS'] = true;
        }
        if (pattern.label === 'TS/SCI') {
          seen['Secret'] = true;
          seen['Top Secret'] = true;
          seen['Interim TS'] = true;
          seen['DoD Secret'] = true;
          seen['L2 Cleared'] = true;
          seen['L1 Cleared'] = true;
          seen['Full Scope Polygraph'] = true;
          seen['CI Polygraph'] = true;
        }
        if (pattern.label === 'L2 Cleared') {
          seen['L1 Cleared'] = true;
          seen['Full Scope Polygraph'] = true;
          seen['CI Polygraph'] = true;
          seen['Polygraph'] = true;
          seen['ISSA'] = true;
          seen['ISA'] = true;
          seen['Clearance'] = true;
        }
        if (pattern.label === 'L1 Cleared') {
          seen['CI Polygraph'] = true;
          seen['Polygraph'] = true;
          seen['ISA'] = true;
          seen['Clearance'] = true;
        }
        if (pattern.label === 'Full Scope Polygraph') {
          seen['CI Polygraph'] = true;
          seen['L1 Cleared'] = true;
          seen['Polygraph'] = true;
          seen['ISSA'] = true;
          seen['ISA'] = true;
          seen['Clearance'] = true;
        }
        if (pattern.label === 'CI Polygraph') {
          seen['Polygraph'] = true;
          seen['ISA'] = true;
          seen['Clearance'] = true;
        }
        if (pattern.label === 'Interim TS') {
          seen['Top Secret'] = true;
          seen['Secret'] = true;
        }
        if (pattern.label === 'Top Secret') {
          seen['Secret'] = true;
        }
        if (pattern.label === 'DoD Secret') {
          seen['Secret'] = true;
          seen['Clearance'] = true;
        }
        if (pattern.label === 'Public Trust') {
          seen['Clearance'] = true;
        }
        if (pattern.label === 'Yankee White Clearance') {
          seen['Clearance'] = true;
        }
        seen[pattern.label] = true;
        clearances.push(pattern.label);
      }
    }

    for (var j = 0; j < CITIZENSHIP_PATTERNS.length; j++) {
      var cp = CITIZENSHIP_PATTERNS[j];
      if (cp.regex.test(cleanText)) {
        hasCitizenship = true;
        if (!citizenshipKeyword) {
          citizenshipKeyword = cp.label;
        }
        if (cp.label === 'US Citizenship') {
          break;
        }
      }
    }

    // Suppress US Citizen badge if "Permanent resident" appears as an answer
    if (hasCitizenship && /(?:Answer\s*:\s*|A\.\s*)Permanent\s+resident/i.test(cleanText)) {
      hasCitizenship = false;
      citizenshipKeyword = null;
    }

    return { clearances: clearances, hasCitizenship: hasCitizenship, citizenshipKeyword: citizenshipKeyword };
  }

  // ── DataExtractor ───────────────────────────────────────────────────
  /**
   * Configurable CSS selectors for hire.amazon.com DOM elements.
   * Update these if the site's DOM structure changes.
   */
  var DATA_EXTRACTOR_SELECTORS = {
    candidateCard: '[data-test-id="resultCards-parent"]',
    candidateName: '[data-test-id="resultCard-name"]',
    resumeSection: '[data-test-id="job-experience-col"]',
    notesSection: '[data-test-id="visible-skills"]',
    questionsSection: '[data-test-id="education-text"]',
    searchResultsWrapper: '[data-test-id="search-results-wrapper"]',
    searchCardHeader: '[data-test-id="search-card-header"]',
  };

  /**
   * Extracts text content from a single section within a candidate card.
   * Logs an error and returns empty string if the section is missing.
   * @param {HTMLElement} cardElement
   * @param {string} selector - CSS selector for the section
   * @param {string} candidateName - Name of the candidate (for error logging)
   * @param {string} sourceName - Human-readable name of the source (for error logging)
   * @returns {string}
   */
  function extractSection(cardElement, selector, candidateName, sourceName) {
    var section = cardElement.querySelector(selector);
    if (!section) {
      // Silently return empty — these sections may not exist on every card
      return '';
    }
    return section.textContent || '';
  }

  /**
   * Extracts text from all profile data sources for a single candidate card element.
   * Returns a CandidateData object, or null if the card has no identifiable name element.
   * @param {HTMLElement} cardElement
   * @returns {{ cardElement: HTMLElement, candidateName: string, resumeText: string, notesText: string, questionsText: string } | null}
   */
  function extractOne(cardElement) {
    var nameEl = cardElement.querySelector(DATA_EXTRACTOR_SELECTORS.candidateName);
    var candidateName = nameEl ? (nameEl.textContent || '').trim() : 'Unknown';

    // Extract text from specific sections, falling back gracefully
    var resumeText = extractSection(
      cardElement,
      DATA_EXTRACTOR_SELECTORS.resumeSection,
      candidateName,
      'job experience'
    );
    var notesText = extractSection(
      cardElement,
      DATA_EXTRACTOR_SELECTORS.notesSection,
      candidateName,
      'skills'
    );
    var questionsText = extractSection(
      cardElement,
      DATA_EXTRACTOR_SELECTORS.questionsSection,
      candidateName,
      'education'
    );

    // Also grab the full card text as a fallback to catch any clearance/citizenship
    // keywords that might appear in chips, labels, or other sections
    var fullCardText = cardElement.textContent || '';

    return {
      cardElement: cardElement,
      candidateName: candidateName,
      resumeText: resumeText,
      notesText: notesText,
      questionsText: questionsText,
      fullCardText: fullCardText,
    };
  }

  /**
   * Extracts text from all profile data sources for all candidate cards on the page.
   * @returns {Array<{ cardElement: HTMLElement, candidateName: string, resumeText: string, notesText: string, questionsText: string }>}
   */
  function extractAll() {
    var cards = document.querySelectorAll(DATA_EXTRACTOR_SELECTORS.candidateCard);
    var results = [];
    for (var i = 0; i < cards.length; i++) {
      var data = extractOne(cards[i]);
      if (data) {
        results.push(data);
      }
    }
    return results;
  }

  // ── BadgeRenderer ─────────────────────────────────────────────────────

  /**
   * Post-processing dedup: removes redundant lower-level badges from a clearances array.
   * This ensures cached results from before dedup fixes are also cleaned up.
   */
  function dedupClearances(clearances) {
    var dominated = {};
    var dominated_by = {
      'TS/SCI with Full Scope Polygraph': ['TS/SCI with CI Polygraph','TS/SCI with Polygraph','TS/SCI','Full Scope Polygraph','CI Polygraph','Polygraph','ISSA','ISA','Clearance','Secret','Top Secret','Interim TS','DoD Secret','L2 Cleared','L1 Cleared'],
      'TS/SCI with CI Polygraph': ['TS/SCI with Polygraph','TS/SCI','CI Polygraph','Polygraph','ISA','Clearance','Secret','Top Secret','Interim TS','L1 Cleared'],
      'TS/SCI with Polygraph': ['TS/SCI','Polygraph','ISA','ISSA','Clearance','Secret','Top Secret','Interim TS'],
      'TS/SCI': ['Secret','Top Secret','Interim TS','DoD Secret','L2 Cleared','L1 Cleared','Full Scope Polygraph','CI Polygraph'],
      'L2 Cleared': ['L1 Cleared','Full Scope Polygraph','CI Polygraph','Polygraph','ISSA','ISA','Clearance'],
      'L1 Cleared': ['CI Polygraph','Polygraph','ISA','Clearance'],
      'Full Scope Polygraph': ['CI Polygraph','Polygraph','ISSA','ISA','Clearance','L1 Cleared'],
      'CI Polygraph': ['Polygraph','ISA','Clearance'],
      'Top Secret': ['Secret'],
      'Interim TS': ['Top Secret','Secret'],
      'DoD Secret': ['Secret','Clearance'],
      'Public Trust': ['Clearance'],
      'Yankee White Clearance': ['Clearance'],
    };
    for (var i = 0; i < clearances.length; i++) {
      var subs = dominated_by[clearances[i]];
      if (subs) {
        for (var j = 0; j < subs.length; j++) {
          dominated[subs[j]] = true;
        }
      }
    }
    return clearances.filter(function (c) { return !dominated[c]; });
  }

  /**
   * Badge configuration for clearance keywords.
   * Maps clearance label to display text and CSS color class.
   */
  var CLEARANCE_BADGE_CONFIG = {
    'TS/SCI with Full Scope Polygraph': { text: 'TS/SCI + L2', colorClass: 'hsc-badge-fsp' },
    'TS/SCI with CI Polygraph':  { text: 'TS/SCI + L1', colorClass: 'hsc-badge-ci-poly' },
    'TS/SCI with Polygraph': { text: 'TS/SCI + Poly', colorClass: 'hsc-badge-tssci-poly' },
    'TS/SCI':                { text: 'TS/SCI',      colorClass: 'hsc-badge-tssci' },
    'L2 Cleared':            { text: 'L2',           colorClass: 'hsc-badge-fsp' },
    'L1 Cleared':            { text: 'L1',           colorClass: 'hsc-badge-ci-poly' },
    'Interim TS':            { text: 'Interim TS',   colorClass: 'hsc-badge-top-secret' },
    'Top Secret':            { text: 'Top Secret',   colorClass: 'hsc-badge-top-secret' },
    'DoD Secret':            { text: 'DoD Secret',   colorClass: 'hsc-badge-secret' },
    'Public Trust':          { text: 'Public Trust',  colorClass: 'hsc-badge-clearance' },
    'Secret':                { text: 'Secret',        colorClass: 'hsc-badge-secret' },
    'DOE Q':                 { text: 'DOE Q',         colorClass: 'hsc-badge-doe-q' },
    'Yankee White Clearance':{ text: 'Yankee White',  colorClass: 'hsc-badge-clearance' },
  };

  /**
   * Badge configuration for citizenship keywords.
   */
  var CITIZENSHIP_BADGE_CONFIG = {
    text: 'US Citizen',
    colorClass: 'hsc-badge-citizenship',
  };

  /**
   * Injects badge CSS styles into document.head.
   * Appends a <style> element with color-coded badge classes namespaced with hsc- prefix.
   * Idempotent — will not inject twice.
   */
  function injectStyles() {
    if (document.getElementById('hsc-badge-styles')) {
      return;
    }
    var style = document.createElement('style');
    style.id = 'hsc-badge-styles';
    style.textContent = [
      '.hsc-badge {',
      '  display: inline-block;',
      '  padding: 2px 6px;',
      '  margin: 0 3px;',
      '  border-radius: 3px;',
      '  font-size: 11px;',
      '  font-weight: 600;',
      '  line-height: 1.4;',
      '  vertical-align: middle;',
      '  white-space: nowrap;',
      '}',
      '.hsc-badge-tssci-poly {',
      '  background-color: #800020;',
      '  color: #ffffff;',
      '}',
      '.hsc-badge-tssci {',
      '  background-color: #cc0000;',
      '  color: #ffffff;',
      '}',
      '.hsc-badge-top-secret {',
      '  background-color: #e67300;',
      '  color: #ffffff;',
      '}',
      '.hsc-badge-secret {',
      '  background-color: #ccaa00;',
      '  color: #000000;',
      '}',
      '.hsc-badge-doe-q {',
      '  background-color: #6a0dad;',
      '  color: #ffffff;',
      '}',
      '.hsc-badge-clearance {',
      '  background-color: #0066cc;',
      '  color: #ffffff;',
      '}',
      '.hsc-badge-ci-poly {',
      '  background-color: #b35900;',
      '  color: #ffffff;',
      '}',
      '.hsc-badge-fsp {',
      '  background-color: #800020;',
      '  color: #ffffff;',
      '}',
      '.hsc-badge-citizenship {',
      '  background-color: #228b22;',
      '  color: #ffffff;',
      '}',
      '.hsc-hidden {',
      '  display: none !important;',
      '}',
      '.hsc-clear-btn {',
      '  display: inline-block;',
      '  margin-left: 4px;',
      '  padding: 0 4px;',
      '  cursor: pointer;',
      '  color: #999;',
      '  font-size: 14px;',
      '  font-weight: bold;',
      '  line-height: 1;',
      '  vertical-align: middle;',
      '  border-radius: 50%;',
      '}',
      '.hsc-clear-btn:hover {',
      '  color: #cc0000;',
      '  background: #f0f0f0;',
      '}',
      '.hsc-filter-container {',
      '  display: flex;',
      '  gap: 8px;',
      '  padding: 8px 0;',
      '  margin-bottom: 8px;',
      '}',
      '.hsc-filter-btn {',
      '  padding: 6px 12px;',
      '  border: 1px solid #ccc;',
      '  border-radius: 4px;',
      '  font-size: 13px;',
      '  font-weight: 500;',
      '  cursor: pointer;',
      '  transition: background-color 0.15s, border-color 0.15s;',
      '  user-select: none;',
      '}',
      '.hsc-filter-active {',
      '  background-color: #0073bb;',
      '  color: #ffffff;',
      '  border-color: #0073bb;',
      '}',
      '.hsc-filter-inactive {',
      '  background-color: #ffffff;',
      '  color: #333333;',
      '  border-color: #ccc;',
      '}',
    ].join('\n');
    document.head.appendChild(style);
  }

  /**
   * Removes all previously injected badges from a candidate card.
   * @param {HTMLElement} cardElement
   */
  function clearBadges(cardElement) {
    var containers = cardElement.querySelectorAll('.hsc-badge-container');
    for (var i = 0; i < containers.length; i++) {
      containers[i].parentNode.removeChild(containers[i]);
    }
  }

  /**
   * Renders badges for a candidate card based on match results.
   * Creates badge elements for each detected clearance and citizenship keyword
   * and inserts them next to the candidate name element.
   * @param {HTMLElement} cardElement
   * @param {{ clearances: string[], hasCitizenship: boolean, citizenshipKeyword: string|null }} matchResult
   */
  /**
   * Adds a clear button to a badge container for the CDP page.
   */
  function addClearButtonCDP(container) {
    var clearBtn = document.createElement('span');
    clearBtn.className = 'hsc-clear-btn';
    clearBtn.textContent = '×';
    clearBtn.title = 'Clear badges for this candidate';
    clearBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      e.preventDefault();
      var personMatch = window.location.pathname.match(/\/person\/(\d+)/);
      var uuidMatch = window.location.pathname.match(/\/([0-9a-f]{8}-[0-9a-f-]+)/);
      var cache = loadCache();
      if (personMatch) delete cache['person:' + personMatch[1]];
      if (uuidMatch) delete cache[uuidMatch[1]];
      var nameEl = document.querySelector('h1, h2');
      if (nameEl) {
        var name = nameEl.textContent.replace(/ID:\s*\d+/, '').trim();
        delete cache['name:' + name];
      }
      saveCache(cache);
      container.remove();
      console.log('[HSC] Cleared badges for current candidate');
    });
    container.appendChild(clearBtn);
  }

  function renderBadges(cardElement, matchResult) {
    // Clear any existing badges first
    clearBadges(cardElement);

    // Post-process dedup to clean up cached or merged results
    var cleanClearances = dedupClearances(matchResult.clearances);

    // If no matches, do nothing (Requirement 5.6)
    if (cleanClearances.length === 0 && !matchResult.hasCitizenship) {
      return;
    }

    // Find the candidate name element to insert badges next to
    var nameEl = cardElement.querySelector(DATA_EXTRACTOR_SELECTORS.candidateName);
    if (!nameEl) {
      return;
    }

    // Create a container for badges
    var container = document.createElement('span');
    container.className = 'hsc-badge-container';
    container.style.marginLeft = '6px';

    // Add clearance badges
    for (var i = 0; i < cleanClearances.length; i++) {
      var clearanceLabel = cleanClearances[i];
      var config = CLEARANCE_BADGE_CONFIG[clearanceLabel];
      if (config) {
        var badge = document.createElement('span');
        badge.className = 'hsc-badge ' + config.colorClass;
        badge.textContent = config.text;
        container.appendChild(badge);
      }
    }

    // Add citizenship badge if applicable
    if (matchResult.hasCitizenship) {
      var citizenBadge = document.createElement('span');
      citizenBadge.className = 'hsc-badge ' + CITIZENSHIP_BADGE_CONFIG.colorClass;
      citizenBadge.textContent = CITIZENSHIP_BADGE_CONFIG.text;
      container.appendChild(citizenBadge);
    }

    // Add clear button
    var clearBtn = document.createElement('span');
    clearBtn.className = 'hsc-clear-btn';
    clearBtn.textContent = '×';
    clearBtn.title = 'Clear badges for this candidate';
    clearBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      e.preventDefault();
      // Find candidate ID and remove from cache
      var cardEl = cardElement.closest ? cardElement : cardElement.parentElement;
      var cid = getCandidateId(cardEl);
      if (cid) {
        var cache = loadCache();
        delete cache[cid];
        // Also delete name-based key
        var nameEl2 = cardElement.querySelector(DATA_EXTRACTOR_SELECTORS.candidateName);
        if (nameEl2) {
          var nameKey = 'name:' + (nameEl2.textContent || '').trim();
          delete cache[nameKey];
        }
        saveCache(cache);
        console.log('[HSC] Cleared cache for', cid);
      }
      // Also try person: key for CDP
      var personMatch = window.location.pathname.match(/\/person\/(\d+)/);
      if (personMatch) {
        var cache2 = loadCache();
        delete cache2['person:' + personMatch[1]];
        saveCache(cache2);
        console.log('[HSC] Cleared cache for person:' + personMatch[1]);
      }
      // Remove badges from DOM
      clearBadges(cardElement);
      var containers = cardElement.querySelectorAll('.hsc-badge-container');
      containers.forEach(function (c) { c.remove(); });
      // Also check parent for CDP
      var parentContainer = nameEl.parentElement.querySelector('.hsc-badge-container');
      if (parentContainer) parentContainer.remove();
    });
    container.appendChild(clearBtn);

    // Insert badge container after the name element
    nameEl.parentNode.insertBefore(container, nameEl.nextSibling);
  }

  // ── FilterController ──────────────────────────────────────────────────

  /**
   * Creates filter toggle button elements and inserts them into the search
   * interface area of the page. Each button has active/inactive CSS classes.
   * Returns the container element for testability.
   * @returns {HTMLElement} The filter container element
   */
  function injectControls() {
    // Remove existing controls if present (idempotent)
    var existing = document.querySelector('.hsc-filter-container');
    if (existing) {
      existing.parentNode.removeChild(existing);
    }

    var container = document.createElement('div');
    container.className = 'hsc-filter-container';

    var clearanceBtn = document.createElement('button');
    clearanceBtn.className = 'hsc-filter-btn hsc-filter-inactive';
    clearanceBtn.setAttribute('data-hsc-filter', 'clearance');
    clearanceBtn.textContent = 'Clearance Filter';
    clearanceBtn.type = 'button';

    var citizenshipBtn = document.createElement('button');
    citizenshipBtn.className = 'hsc-filter-btn hsc-filter-inactive';
    citizenshipBtn.setAttribute('data-hsc-filter', 'citizenship');
    citizenshipBtn.textContent = 'Citizenship Filter';
    citizenshipBtn.type = 'button';

    container.appendChild(clearanceBtn);
    container.appendChild(citizenshipBtn);

    // Insert at the top of the search results area
    var searchResults = document.querySelector('[data-test-id="search-results-wrapper"]') ||
                        document.querySelector('[data-search-results], .search-results');
    if (searchResults) {
      searchResults.insertBefore(container, searchResults.firstChild);
    } else {
      // Fallback: insert at the top of body
      document.body.insertBefore(container, document.body.firstChild);
    }

    return container;
  }

  /**
   * Applies the current filter state to all candidate cards.
   * Toggles the `hsc-hidden` CSS class based on filter criteria.
   * When both filters are active, a card must have BOTH clearance AND citizenship to remain visible.
   * @param {{ clearanceFilterActive: boolean, citizenshipFilterActive: boolean }} filterState
   * @param {Map<HTMLElement, { clearances: string[], hasCitizenship: boolean, citizenshipKeyword: string|null }>} candidateResults
   */
  function applyFilters(filterState, candidateResults) {
    candidateResults.forEach(function (matchResult, cardElement) {
      var shouldHide = false;

      if (filterState.clearanceFilterActive && matchResult.clearances.length === 0) {
        shouldHide = true;
      }

      if (filterState.citizenshipFilterActive && !matchResult.hasCitizenship) {
        shouldHide = true;
      }

      if (shouldHide) {
        cardElement.classList.add('hsc-hidden');
      } else {
        cardElement.classList.remove('hsc-hidden');
      }
    });
  }

  /**
   * Updates the visual state of filter toggle buttons to reflect the current filter state.
   * @param {{ clearanceFilterActive: boolean, citizenshipFilterActive: boolean }} filterState
   */
  function updateFilterButtonStates(filterState) {
    var clearanceBtn = document.querySelector('[data-hsc-filter="clearance"]');
    var citizenshipBtn = document.querySelector('[data-hsc-filter="citizenship"]');

    if (clearanceBtn) {
      clearanceBtn.classList.toggle('hsc-filter-active', filterState.clearanceFilterActive);
      clearanceBtn.classList.toggle('hsc-filter-inactive', !filterState.clearanceFilterActive);
    }

    if (citizenshipBtn) {
      citizenshipBtn.classList.toggle('hsc-filter-active', filterState.citizenshipFilterActive);
      citizenshipBtn.classList.toggle('hsc-filter-inactive', !filterState.citizenshipFilterActive);
    }
  }

  // ── FilterPersistence ────────────────────────────────────────────────

  var STORAGE_KEY = 'hsc-filter-prefs';

  /**
   * Default filter state with both filters inactive.
   * @returns {{ clearanceFilterActive: boolean, citizenshipFilterActive: boolean }}
   */
  function defaultFilterState() {
    return { clearanceFilterActive: false, citizenshipFilterActive: false };
  }

  /**
   * Saves filter state to localStorage as JSON.
   * Logs console.warn on failure (e.g. localStorage unavailable).
   * @param {{ clearanceFilterActive: boolean, citizenshipFilterActive: boolean }} state
   */
  function saveFilterState(state) {
    try {
      GM_setValue(STORAGE_KEY, JSON.stringify(state));
    } catch (e) {
      console.warn('[HSC] Failed to save filter preferences:', e);
    }
  }

  /**
   * Loads filter state from GM storage.
   * Returns default state (both filters inactive) on any failure.
   * @returns {{ clearanceFilterActive: boolean, citizenshipFilterActive: boolean }}
   */
  function loadFilterState() {
    try {
      var raw = GM_getValue(STORAGE_KEY, null);
      if (raw === null) {
        return defaultFilterState();
      }
      var parsed = JSON.parse(raw);
      return {
        clearanceFilterActive: !!parsed.clearanceFilterActive,
        citizenshipFilterActive: !!parsed.citizenshipFilterActive,
      };
    } catch (e) {
      console.warn('[HSC] Failed to load filter preferences:', e);
      return defaultFilterState();
    }
  }

  // ── ClearanceCache ─────────────────────────────────────────────────────
  var CACHE_KEY = 'hsc-clearance-cache';

  function loadCache() {
    try {
      var raw = GM_getValue(CACHE_KEY, '{}');
      var cache = JSON.parse(raw);
      // If GM storage is empty, try restoring from localStorage backup
      if (Object.keys(cache).length === 0) {
        try {
          var backup = localStorage.getItem(CACHE_KEY);
          if (backup) {
            cache = JSON.parse(backup);
            if (Object.keys(cache).length > 0) {
              GM_setValue(CACHE_KEY, backup);
              console.log('[HSC] Cache restored from localStorage backup:', Object.keys(cache).length, 'entries');
            }
          }
        } catch (e2) { /* localStorage unavailable */ }
      }
      return cache;
    } catch (e) { return {}; }
  }

  function saveCache(cache) {
    try {
      var json = JSON.stringify(cache);
      GM_setValue(CACHE_KEY, json);
      // Also save to localStorage as backup
      try { localStorage.setItem(CACHE_KEY, json); } catch (e2) { /* localStorage full or unavailable */ }
    } catch (e) { console.warn('[HSC] Cache save failed:', e); }
  }

  function cacheResult(candidateId, matchResult, candidateName) {
    if (!candidateId) return;
    var cache = loadCache();
    cache[candidateId] = {
      clearances: matchResult.clearances,
      hasCitizenship: matchResult.hasCitizenship,
      citizenshipKeyword: matchResult.citizenshipKeyword,
      candidateName: candidateName || null,
      ts: Date.now(),
    };
    // Also store under name key for cross-referencing
    if (candidateName) {
      cache['name:' + candidateName] = cache[candidateId];
    }
    saveCache(cache);
  }

  function getCachedResult(candidateId) {
    if (!candidateId) return null;
    var cache = loadCache();
    var entry = cache[candidateId];
    if (!entry) return null;
    return { clearances: entry.clearances, hasCitizenship: entry.hasCitizenship, citizenshipKeyword: entry.citizenshipKeyword };
  }

  function getCandidateId(cardElement) {
    // The card element is [data-test-id="resultCards-parent"]
    // Its parent div has the candidate UUID as data-test-id
    var parent = cardElement.parentElement;
    if (parent) {
      var parentId = parent.getAttribute('data-test-id');
      if (parentId && /^[0-9a-f]{8}-/.test(parentId)) return parentId;
    }
    // The card itself might have the UUID
    var testId = cardElement.getAttribute('data-test-id');
    if (testId && testId !== 'resultCards-parent' && /^[0-9a-f]{8}-/.test(testId)) return testId;
    // Try finding the name link which might have an href with the ID
    var nameLink = cardElement.querySelector('[data-test-id="resultCard-name"]');
    if (nameLink && nameLink.href) {
      var hrefMatch = nameLink.href.match(/\/([0-9a-f]{8}-[0-9a-f-]+)/);
      if (hrefMatch) return hrefMatch[1];
    }
    // Fallback: use candidate name as key
    if (nameLink) return 'name:' + (nameLink.textContent || '').trim();
    return null;
  }

  // ── DetailPageSupport ────────────────────────────────────────────────
  function isDetailPage() {
    return /\/(person|sourcing\/candidates|candidates)\//.test(window.location.pathname);
  }

  function isJobDetailPage() {
    return /\/reqs\//.test(window.location.pathname);
  }

  function isApplicantsPage() {
    return /^\/ar\b/.test(window.location.pathname);
  }

  function handleApplicantsPage() {
    injectStyles();
    var scannedPersons = {};

    function scanApplicants() {
      var rows = document.querySelectorAll('tr');
      rows.forEach(function (row) {
        var personLink = row.querySelector('a[href*="/person/"]');
        if (!personLink) return;

        var personMatch = personLink.href.match(/\/person\/(\d+)/);
        if (!personMatch) return;
        var personId = personMatch[1];

        // Find job iCIMS ID from the row
        var jobCell = row.querySelectorAll('td')[3];
        if (!jobCell) return;
        var jobIdMatch = jobCell.textContent.match(/ID:\s*(\d+)/);
        if (!jobIdMatch) return;
        var jobId = jobIdMatch[1];

        // Skip if already scanned or has badges
        var key = personId + ':' + jobId;
        if (scannedPersons[key]) return;
        if (personLink.parentElement.querySelector('.hsc-badge-container')) return;

        // Check cache first
        var cached = getCachedResult('person:' + personId);
        if (cached && (cached.clearances.length > 0 || cached.hasCitizenship)) {
          injectBadgeNextToLink(personLink, cached);
          scannedPersons[key] = true;
          return;
        }

        scannedPersons[key] = true;

        // Query the API for screening questions
        fetch('/ar/api/graphql', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({query: '{ getApplicationQuestions(personIcimsId: "' + personId + '", jobIcimsId: "' + jobId + '") { formSections { questions { title answer } } } }'}),
          credentials: 'include'
        }).then(function (r) { return r.json(); }).then(function (data) {
          if (!data.data || !data.data.getApplicationQuestions) return;
          var sections = data.data.getApplicationQuestions.formSections || [];
          var allText = '';
          sections.forEach(function (s) {
            (s.questions || []).forEach(function (q) {
              if (q.answer) allText += ' Answer: ' + q.answer;
            });
          });
          if (allText.length < 5) return;

          var apiMatch = match(allText);
          if (apiMatch.clearances.length === 0 && !apiMatch.hasCitizenship) return;

          // Merge with existing cache to preserve citizenship
          var existingCache = getCachedResult('person:' + personId) || { clearances: [], hasCitizenship: false, citizenshipKeyword: null };
          var mergedApi = {
            clearances: apiMatch.clearances.slice(),
            hasCitizenship: existingCache.hasCitizenship || apiMatch.hasCitizenship,
            citizenshipKeyword: existingCache.citizenshipKeyword || apiMatch.citizenshipKeyword,
          };
          for (var ec = 0; ec < existingCache.clearances.length; ec++) {
            if (mergedApi.clearances.indexOf(existingCache.clearances[ec]) === -1) {
              mergedApi.clearances.push(existingCache.clearances[ec]);
            }
          }
          mergedApi.clearances = dedupClearances(mergedApi.clearances);

          var candidateName = personLink.textContent.trim();
          cacheResult('person:' + personId, mergedApi, candidateName);
          injectBadgeNextToLink(personLink, mergedApi);
        }).catch(function () { /* API error, skip */ });
      });
    }

    function injectBadgeNextToLink(link, matchResult) {
      if (link.parentElement.querySelector('.hsc-badge-container')) return;
      var cleanClearances = dedupClearances(matchResult.clearances);
      var container = document.createElement('span');
      container.className = 'hsc-badge-container';
      container.style.marginLeft = '6px';
      for (var i = 0; i < cleanClearances.length; i++) {
        var config = CLEARANCE_BADGE_CONFIG[cleanClearances[i]];
        if (config) {
          var badge = document.createElement('span');
          badge.className = 'hsc-badge ' + config.colorClass;
          badge.textContent = config.text;
          container.appendChild(badge);
        }
      }
      if (matchResult.hasCitizenship) {
        var cb = document.createElement('span');
        cb.className = 'hsc-badge ' + CITIZENSHIP_BADGE_CONFIG.colorClass;
        cb.textContent = CITIZENSHIP_BADGE_CONFIG.text;
        container.appendChild(cb);
      }
      link.parentElement.insertBefore(container, link.nextSibling);
    }

    // Initial scan after page loads
    setTimeout(scanApplicants, 2000);
    // Re-scan periodically for pagination/tab changes
    setInterval(scanApplicants, 5000);
  }

  function injectJdpBadge(link, matchResult) {
    if (link.parentElement.querySelector('.hsc-badge-container')) return;
    var cleanClearances = dedupClearances(matchResult.clearances);
    var container = document.createElement('span');
    container.className = 'hsc-badge-container';
    container.style.marginLeft = '6px';
    for (var i = 0; i < cleanClearances.length; i++) {
      var config = CLEARANCE_BADGE_CONFIG[cleanClearances[i]];
      if (config) {
        var badge = document.createElement('span');
        badge.className = 'hsc-badge ' + config.colorClass;
        badge.textContent = config.text;
        container.appendChild(badge);
      }
    }
    if (matchResult.hasCitizenship) {
      var cb = document.createElement('span');
      cb.className = 'hsc-badge ' + CITIZENSHIP_BADGE_CONFIG.colorClass;
      cb.textContent = CITIZENSHIP_BADGE_CONFIG.text;
      container.appendChild(cb);
    }
    link.parentElement.insertBefore(container, link.nextSibling);
  }

  function handleJobDetailPage() {
    injectStyles();
    var jdpScannedPersons = {};

    // Get job iCIMS ID from URL
    var jobIcimsId = (window.location.search.match(/jobs_filter=(\d+)/) || [])[1];

    // Poll for candidate name links and inject cached badges or query API
    setInterval(function () {
      var personLinks = document.querySelectorAll('a[href*="/person/"]');
      personLinks.forEach(function (link) {
        // Skip if already has badges
        if (link.parentElement.querySelector('.hsc-badge-container')) return;

        var href = link.getAttribute('href') || '';
        var personMatch = href.match(/\/person\/(\d+)/);
        if (!personMatch) return;

        var pid = personMatch[1];
        var personId = 'person:' + pid;
        var candidateName = link.textContent.trim();
        var nameKey = 'name:' + candidateName;

        // Try cache first
        var cached = getCachedResult(personId) || getCachedResult(nameKey);
        if (cached && (cached.clearances.length > 0 || cached.hasCitizenship)) {
          injectJdpBadge(link, cached);
          return;
        }

        // If no cache and we have a job ID, query the API
        if (!jobIcimsId) return;
        var scanKey = pid + ':' + jobIcimsId;
        if (jdpScannedPersons[scanKey]) return;
        jdpScannedPersons[scanKey] = true;

        fetch('/ar/api/graphql', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({query: '{ getApplicationQuestions(personIcimsId: "' + pid + '", jobIcimsId: "' + jobIcimsId + '") { formSections { questions { title answer } } } }'}),
          credentials: 'include'
        }).then(function (r) { return r.json(); }).then(function (data) {
          if (!data.data || !data.data.getApplicationQuestions) return;
          var sections = data.data.getApplicationQuestions.formSections || [];
          var allText = '';
          sections.forEach(function (s) {
            (s.questions || []).forEach(function (q) {
              if (q.answer) allText += ' Answer: ' + q.answer;
            });
          });
          if (allText.length < 5) return;
          var apiMatch = match(allText);
          if (apiMatch.clearances.length === 0 && !apiMatch.hasCitizenship) return;
          // Merge with existing cache to preserve citizenship
          var existingJdp = getCachedResult(personId) || { clearances: [], hasCitizenship: false, citizenshipKeyword: null };
          var mergedJdp = {
            clearances: apiMatch.clearances.slice(),
            hasCitizenship: existingJdp.hasCitizenship || apiMatch.hasCitizenship,
            citizenshipKeyword: existingJdp.citizenshipKeyword || apiMatch.citizenshipKeyword,
          };
          for (var ej = 0; ej < existingJdp.clearances.length; ej++) {
            if (mergedJdp.clearances.indexOf(existingJdp.clearances[ej]) === -1) {
              mergedJdp.clearances.push(existingJdp.clearances[ej]);
            }
          }
          mergedJdp.clearances = dedupClearances(mergedJdp.clearances);
          cacheResult(personId, mergedJdp, candidateName);
          injectJdpBadge(link, mergedJdp);
        }).catch(function () {});
      });

      // Scan Rapid Review flyout dialog for screening question answers
      var dialog = document.querySelector('[role="dialog"]');
      if (dialog && !dialog.getAttribute('data-hsc-scanned')) {
        var dialogText = dialog.textContent || '';
        if (dialogText.length > 100) {
          // Clone and strip our badges
          var clone = dialog.cloneNode(true);
          clone.querySelectorAll('.hsc-badge-container, .hsc-badge').forEach(function (b) { b.remove(); });
          var cleanDialogText = clone.textContent || '';

          var dialogMatch = match(cleanDialogText);
          if (dialogMatch.clearances.length > 0 || dialogMatch.hasCitizenship) {
            // Find person ID from dialog text
            var idMatch = cleanDialogText.match(/ID:\s*(\d+)/);
            if (idMatch) {
              var pid = 'person:' + idMatch[1];
              // Find candidate name from dialog
              var nameMatch = cleanDialogText.match(/(?:Previous|Next)([A-Z][a-z]+ [A-Z][a-z]+)/);
              var cName = nameMatch ? nameMatch[1] : null;
              cacheResult(pid, dialogMatch, cName);
            }

            // Inject badges in the dialog header
            var dialogNameEl = dialog.querySelector('a[href*="/person/"]');
            if (dialogNameEl && !dialogNameEl.parentElement.querySelector('.hsc-badge-container')) {
              var dc = document.createElement('span');
              dc.className = 'hsc-badge-container';
              dc.style.marginLeft = '6px';
              var cleanD = dedupClearances(dialogMatch.clearances);
              for (var di = 0; di < cleanD.length; di++) {
                var dcfg = CLEARANCE_BADGE_CONFIG[cleanD[di]];
                if (dcfg) {
                  var db = document.createElement('span');
                  db.className = 'hsc-badge ' + dcfg.colorClass;
                  db.textContent = dcfg.text;
                  dc.appendChild(db);
                }
              }
              if (dialogMatch.hasCitizenship) {
                var dcit = document.createElement('span');
                dcit.className = 'hsc-badge ' + CITIZENSHIP_BADGE_CONFIG.colorClass;
                dcit.textContent = CITIZENSHIP_BADGE_CONFIG.text;
                dc.appendChild(dcit);
              }
              dialogNameEl.parentElement.insertBefore(dc, dialogNameEl.nextSibling);
            }
          }
          dialog.setAttribute('data-hsc-scanned', 'true');
        }
      }
      // Reset scan flag when dialog changes (next/previous candidate)
      if (!dialog) {
        document.querySelectorAll('[data-hsc-scanned]').forEach(function (el) {
          el.removeAttribute('data-hsc-scanned');
        });
      }
    }, 3000);
  }

  function handleDetailPage() {
    injectStyles();

    // Try to find candidate UUID in the page HTML
    function findCandidateUUID() {
      // Priority 1: Use person ID from URL
      var numericMatch = window.location.pathname.match(/\/person\/(\d+)/);
      if (numericMatch) return 'person:' + numericMatch[1];

      // Priority 2: Use UUID from URL
      var uuidMatch = window.location.pathname.match(/\/([0-9a-f]{8}-[0-9a-f-]+)/);
      if (uuidMatch) return uuidMatch[1];

      // Priority 3: Use candidate name from page header
      var nameEl = document.querySelector('h1, h2');
      if (nameEl) {
        var name = nameEl.textContent.replace(/ID:\s*\d+/, '').trim();
        if (name) return 'name:' + name;
      }

      return null;
    }

    function tryInjectBadges() {
      var candidateId = findCandidateUUID();
      if (!candidateId) return false;

      var cached = getCachedResult(candidateId);
      if (!cached || (cached.clearances.length === 0 && !cached.hasCitizenship)) return false;

      // Find the name element
      var nameEl = document.querySelector('h1, h2');
      if (!nameEl) return false;

      // Don't inject twice
      if (nameEl.parentElement.querySelector('.hsc-badge-container')) return true;

      var container = document.createElement('span');
      container.className = 'hsc-badge-container';
      container.style.marginLeft = '10px';

      var cleanCached = dedupClearances(cached.clearances);
      for (var i = 0; i < cleanCached.length; i++) {
        var config = CLEARANCE_BADGE_CONFIG[cleanCached[i]];
        if (config) {
          var badge = document.createElement('span');
          badge.className = 'hsc-badge ' + config.colorClass;
          badge.textContent = config.text;
          container.appendChild(badge);
        }
      }
      if (cached.hasCitizenship) {
        var citizenBadge = document.createElement('span');
        citizenBadge.className = 'hsc-badge ' + CITIZENSHIP_BADGE_CONFIG.colorClass;
        citizenBadge.textContent = CITIZENSHIP_BADGE_CONFIG.text;
        container.appendChild(citizenBadge);
      }

      addClearButtonCDP(container);
      nameEl.parentElement.insertBefore(container, nameEl.nextSibling);
      console.log('[HSC] Badges injected on detail page from cache for:', candidateId);
      return true;
    }

    // Wait for page content to load, then try injecting
    var attempts = 0;
    var detailInterval = setInterval(function () {
      attempts++;
      if (tryInjectBadges() || attempts > 20) {
        clearInterval(detailInterval);
      }
    }, 500);

    // Also scan the PDF if one is present on the CDP
    setupFlyoutObserver();

    // Watch for cross-origin PDF iframes (S3-hosted resumes on CDP)
    var crossOriginScanned = {};
    var cdpPdfObserver = new MutationObserver(function (mutations) {
      var hasNew = mutations.some(function (m) { return m.addedNodes.length > 0; });
      if (!hasNew) return;

      var iframes = document.querySelectorAll('iframe');
      iframes.forEach(function (iframe) {
        var src = iframe.src || '';
        if (src.indexOf('amazonaws.com') === -1) return;
        if (crossOriginScanned[src]) return;
        crossOriginScanned[src] = true;

        tryCrossOriginPDFScan(src, function (pdfMatch) {
          if (pdfMatch.clearances.length === 0 && !pdfMatch.hasCitizenship) return;

          var cid = findCandidateUUID();
          if (!cid) return;

          var nameEl = document.querySelector('h1, h2');
          var cName = nameEl ? nameEl.textContent.replace(/ID:\s*\d+/, '').trim() : null;
          cacheResult(cid, pdfMatch, cName);

          // Inject/update badges
          if (nameEl) {
            var existing = nameEl.parentElement.querySelector('.hsc-badge-container');
            if (existing) existing.remove();

            var cleanClearances = dedupClearances(pdfMatch.clearances);
            var container = document.createElement('span');
            container.className = 'hsc-badge-container';
            container.style.marginLeft = '10px';

            for (var p = 0; p < cleanClearances.length; p++) {
              var cfg = CLEARANCE_BADGE_CONFIG[cleanClearances[p]];
              if (cfg) {
                var badge = document.createElement('span');
                badge.className = 'hsc-badge ' + cfg.colorClass;
                badge.textContent = cfg.text;
                container.appendChild(badge);
              }
            }
            if (pdfMatch.hasCitizenship) {
              var cb = document.createElement('span');
              cb.className = 'hsc-badge ' + CITIZENSHIP_BADGE_CONFIG.colorClass;
              cb.textContent = CITIZENSHIP_BADGE_CONFIG.text;
              container.appendChild(cb);
            }
            addClearButtonCDP(container);
            nameEl.parentElement.insertBefore(container, nameEl.nextSibling);
            console.log('[HSC] Badges updated from cross-origin PDF');
          }
        });
      });
    });
    cdpPdfObserver.observe(document.body, { childList: true, subtree: true });
    setTimeout(function () { cdpPdfObserver.disconnect(); }, 60000);

    // Scan the CDP page text for clearance keywords (screening questions, notes, etc.)
    var cdpScanned = false;
    var cdpLastTextLength = 0;
    var cdpObserver = new MutationObserver(function (mutations) {
      var hasNewNodes = mutations.some(function (m) { return m.addedNodes.length > 0; });
      if (!hasNewNodes) return;

      // Look for screening question content and dialogs
      var questionEls = document.querySelectorAll(
        '[class*="css-1aayaoq"], [class*="css-gb1y2i"], [class*="pdv-pdv"], ' +
        '[class*="e1aayydo"], [class*="e1rrhn7i"]'
      );
      var dialogs = document.querySelectorAll('[role="dialog"], [role="complementary"]');
      if (questionEls.length === 0 && dialogs.length === 0) return;

      clearTimeout(cdpObserver._timer);
      cdpObserver._timer = setTimeout(function () {
        var pageText = '';

        // All screening question elements
        questionEls.forEach(function (el) {
          var clone = el.cloneNode(true);
          clone.querySelectorAll('.hsc-badge-container, .hsc-badge').forEach(function (b) { b.remove(); });
          pageText += ' ' + (clone.textContent || '');
        });

        // Also grab notes — but exclude badge containers
        var notesList = document.querySelector('[data-test-id="notes-list"]');
        if (notesList) {
          var notesClone = notesList.cloneNode(true);
          var badges = notesClone.querySelectorAll('.hsc-badge-container, .hsc-badge');
          badges.forEach(function (b) { b.remove(); });
          pageText += ' ' + notesClone.textContent;
        }

        // Grab any flyout/dialog content — exclude badges
        document.querySelectorAll('[role="dialog"], [role="complementary"]').forEach(function (el) {
          if (el.closest('.hsc-badge-container')) return;
          var clone = el.cloneNode(true);
          var cloneBadges = clone.querySelectorAll('.hsc-badge-container, .hsc-badge');
          cloneBadges.forEach(function (b) { b.remove(); });
          pageText += ' ' + clone.textContent;
        });

        // Strip our own badge label text to prevent self-matching
        var badgeLabels = Object.keys(CLEARANCE_BADGE_CONFIG).map(function (k) { return CLEARANCE_BADGE_CONFIG[k].text; });
        badgeLabels.push(CITIZENSHIP_BADGE_CONFIG.text);
        badgeLabels.forEach(function (label) {
          // Remove exact badge text that appears concatenated with surrounding text (no spaces around it)
          pageText = pageText.split(label).join(' ');
        });

        if (pageText.trim().length < 20) return;
        // Re-scan if text length changed (new content loaded like JSQ flyout)
        if (pageText.length === cdpLastTextLength) return;
        cdpLastTextLength = pageText.length;

        var cdpMatch = match(pageText);
        if (cdpMatch.clearances.length === 0 && !cdpMatch.hasCitizenship) return;

        cdpScanned = true;
        console.log('[HSC] CDP page scan found:', cdpMatch.clearances.join(', '), cdpMatch.hasCitizenship ? '+ citizenship (' + cdpMatch.citizenshipKeyword + ')' : '');

        // Find candidate ID and cache — merge with existing cache, let dedup sort hierarchy
        var candidateId = findCandidateUUID();
        if (candidateId) {
          var existing = getCachedResult(candidateId) || { clearances: [], hasCitizenship: false, citizenshipKeyword: null };
          var merged = {
            clearances: existing.clearances.slice(),
            hasCitizenship: existing.hasCitizenship || cdpMatch.hasCitizenship,
            citizenshipKeyword: existing.citizenshipKeyword || cdpMatch.citizenshipKeyword,
          };
          for (var m = 0; m < cdpMatch.clearances.length; m++) {
            if (merged.clearances.indexOf(cdpMatch.clearances[m]) === -1) {
              merged.clearances.push(cdpMatch.clearances[m]);
            }
          }
          // Dedup removes lower-level badges (e.g., L1 suppressed by L2/FSP)
          merged.clearances = dedupClearances(merged.clearances);
          var cdpNameEl = document.querySelector('h1, h2');
          var cdpCandidateName = cdpNameEl ? cdpNameEl.textContent.replace(/ID:\s*\d+/, '').trim() : null;
          cacheResult(candidateId, merged, cdpCandidateName);

          // Re-inject badges with updated data
          var nameEl = document.querySelector('h1, h2');
          if (nameEl) {
            var existingContainer = nameEl.parentElement.querySelector('.hsc-badge-container');
            if (existingContainer) existingContainer.remove();

            var container = document.createElement('span');
            container.className = 'hsc-badge-container';
            container.style.marginLeft = '10px';

            var cleanMerged = dedupClearances(merged.clearances);
            for (var b = 0; b < cleanMerged.length; b++) {
              var config = CLEARANCE_BADGE_CONFIG[cleanMerged[b]];
              if (config) {
                var badge = document.createElement('span');
                badge.className = 'hsc-badge ' + config.colorClass;
                badge.textContent = config.text;
                container.appendChild(badge);
              }
            }
            if (merged.hasCitizenship) {
              var citizenBadge = document.createElement('span');
              citizenBadge.className = 'hsc-badge ' + CITIZENSHIP_BADGE_CONFIG.colorClass;
              citizenBadge.textContent = CITIZENSHIP_BADGE_CONFIG.text;
              container.appendChild(citizenBadge);
            }
            addClearButtonCDP(container);
            nameEl.parentElement.insertBefore(container, nameEl.nextSibling);
            console.log('[HSC] Badges updated from CDP screening questions');
          }
        }
      }, 1000);
    });
    cdpObserver.observe(document.body, { childList: true, subtree: true });
    // Keep observer alive for 5 minutes
    setTimeout(function () { cdpObserver.disconnect(); }, 300000);

    // Poll for new content every 3 seconds (replaces click listener which doesn't work in TM sandbox)
    setInterval(function () {
      var qEls = document.querySelectorAll(
        '[class*="css-1aayaoq"], [class*="css-gb1y2i"], [class*="pdv-pdv"], ' +
        '[class*="e1aayydo"], [class*="e1rrhn7i"]'
      );
      var dEls = document.querySelectorAll('[role="dialog"], [role="complementary"]');
      if (qEls.length === 0 && dEls.length === 0) return;

      var pollText = '';
      qEls.forEach(function (el) {
        var clone = el.cloneNode(true);
        clone.querySelectorAll('.hsc-badge-container, .hsc-badge').forEach(function (b) { b.remove(); });
        pollText += ' ' + (clone.textContent || '');
      });
      var notesList = document.querySelector('[data-test-id="notes-list"]');
      if (notesList) {
        var nc = notesList.cloneNode(true);
        nc.querySelectorAll('.hsc-badge-container, .hsc-badge').forEach(function (b) { b.remove(); });
        pollText += ' ' + nc.textContent;
      }
      dEls.forEach(function (el) {
        var clone = el.cloneNode(true);
        clone.querySelectorAll('.hsc-badge-container, .hsc-badge').forEach(function (b) { b.remove(); });
        pollText += ' ' + clone.textContent;
      });

      if (pollText.trim().length < 20) return;
      if (pollText.length === cdpLastTextLength) return;
      cdpLastTextLength = pollText.length;

      var pollMatch = match(pollText);
      if (pollMatch.clearances.length === 0 && !pollMatch.hasCitizenship) return;

      console.log('[HSC] Poll scan found:', pollMatch.clearances.join(', '), pollMatch.hasCitizenship ? '+ citizenship' : '');

      var cid = findCandidateUUID();
      if (!cid) return;

      var existing = getCachedResult(cid) || { clearances: [], hasCitizenship: false, citizenshipKeyword: null };
      var pollMerged = {
        clearances: existing.clearances.slice(),
        hasCitizenship: existing.hasCitizenship || pollMatch.hasCitizenship,
        citizenshipKeyword: existing.citizenshipKeyword || pollMatch.citizenshipKeyword,
      };
      for (var pm = 0; pm < pollMatch.clearances.length; pm++) {
        if (pollMerged.clearances.indexOf(pollMatch.clearances[pm]) === -1) {
          pollMerged.clearances.push(pollMatch.clearances[pm]);
        }
      }
      pollMerged.clearances = dedupClearances(pollMerged.clearances);

      var pollNameEl = document.querySelector('h1, h2');
      var pollName = pollNameEl ? pollNameEl.textContent.replace(/ID:\s*\d+/, '').trim() : null;
      cacheResult(cid, pollMerged, pollName);

      if (pollNameEl) {
        var ec = pollNameEl.parentElement.querySelector('.hsc-badge-container');
        if (ec) ec.remove();
        var cleanPoll = dedupClearances(pollMerged.clearances);
        var pc = document.createElement('span');
        pc.className = 'hsc-badge-container';
        pc.style.marginLeft = '10px';
        for (var pb = 0; pb < cleanPoll.length; pb++) {
          var pcfg = CLEARANCE_BADGE_CONFIG[cleanPoll[pb]];
          if (pcfg) {
            var pbadge = document.createElement('span');
            pbadge.className = 'hsc-badge ' + pcfg.colorClass;
            pbadge.textContent = pcfg.text;
            pc.appendChild(pbadge);
          }
        }
        if (pollMerged.hasCitizenship) {
          var pcit = document.createElement('span');
          pcit.className = 'hsc-badge ' + CITIZENSHIP_BADGE_CONFIG.colorClass;
          pcit.textContent = CITIZENSHIP_BADGE_CONFIG.text;
          pc.appendChild(pcit);
        }
        addClearButtonCDP(pc);
        pollNameEl.parentElement.insertBefore(pc, pollNameEl.nextSibling);
        console.log('[HSC] Badges updated from poll scan');
      }
    }, 3000);
  }

  // ── CrossOriginPDFReader ──────────────────────────────────────────────
  /**
   * Fetches a cross-origin PDF via GM_xmlhttpRequest and extracts text.
   * Used on the CDP where the resume iframe points to S3.
   * @param {string} url - The PDF URL
   * @param {function} callback - Called with extracted text string
   */
  function fetchAndExtractPDF(url, callback) {
    GM_xmlhttpRequest({
      method: 'GET',
      url: url,
      responseType: 'arraybuffer',
      onload: function (response) {
        try {
          var data = new Uint8Array(response.response);
          // Use pdf.js to properly extract text from compressed PDFs
          if (typeof pdfjsLib !== 'undefined') {
            pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
            var loadingTask = pdfjsLib.getDocument({ data: data });
            loadingTask.promise.then(function (pdf) {
              var allText = '';
              var pages = [];
              for (var p = 1; p <= pdf.numPages; p++) {
                pages.push(p);
              }
              var processed = 0;
              pages.forEach(function (pageNum) {
                pdf.getPage(pageNum).then(function (page) {
                  page.getTextContent().then(function (content) {
                    var pageText = content.items.map(function (item) { return item.str; }).join(' ');
                    allText += ' ' + pageText;
                    processed++;
                    if (processed === pages.length) {
                      callback(allText.trim());
                    }
                  });
                });
              });
            }).catch(function (err) {
              console.error('[HSC] pdf.js extraction failed:', err);
              callback('');
            });
          } else {
            console.warn('[HSC] pdf.js not loaded, falling back to basic extraction');
            var text = extractTextFromPDFBytes(data);
            callback(text);
          }
        } catch (err) {
          console.error('[HSC] PDF extraction failed:', err);
          callback('');
        }
      },
      onerror: function (err) {
        console.error('[HSC] PDF fetch failed:', err);
        callback('');
      }
    });
  }

  /**
   * Basic PDF text extraction from raw bytes.
   * Extracts text from PDF stream objects by finding text operators (Tj, TJ, ').
   * This is a lightweight approach — won't handle all PDFs but works for most resumes.
   */
  function extractTextFromPDFBytes(bytes) {
    // Convert bytes to string for parsing
    var raw = '';
    for (var i = 0; i < bytes.length; i++) {
      raw += String.fromCharCode(bytes[i]);
    }

    var text = '';

    // Find all stream...endstream blocks and extract text operators
    var streamRegex = /stream\r?\n([\s\S]*?)endstream/g;
    var streamMatch;
    while ((streamMatch = streamRegex.exec(raw)) !== null) {
      var streamData = streamMatch[1];

      // Try to decompress FlateDecode streams
      // Skip binary/compressed streams we can't read
      // Look for readable text in uncompressed streams

      // Extract text between parentheses (Tj operator)
      var tjRegex = /\(([^)]*)\)\s*Tj/g;
      var tjMatch;
      while ((tjMatch = tjRegex.exec(streamData)) !== null) {
        text += tjMatch[1] + ' ';
      }

      // Extract text from TJ arrays [(text) num (text) ...]
      var tjArrayRegex = /\[((?:\([^)]*\)|[^\]])*)\]\s*TJ/g;
      var tjArrMatch;
      while ((tjArrMatch = tjArrayRegex.exec(streamData)) !== null) {
        var inner = tjArrMatch[1];
        var innerRegex = /\(([^)]*)\)/g;
        var innerMatch;
        while ((innerMatch = innerRegex.exec(inner)) !== null) {
          text += innerMatch[1];
        }
        text += ' ';
      }
    }

    // Also try to find text in the raw PDF outside streams (for simple PDFs)
    var rawTjRegex = /\(([^)]{2,})\)\s*Tj/g;
    var rawMatch;
    while ((rawMatch = rawTjRegex.exec(raw)) !== null) {
      if (text.indexOf(rawMatch[1]) === -1) {
        text += rawMatch[1] + ' ';
      }
    }

    // Unescape PDF string escapes
    text = text
      .replace(/\\n/g, '\n')
      .replace(/\\r/g, '\r')
      .replace(/\\t/g, '\t')
      .replace(/\\\(/g, '(')
      .replace(/\\\)/g, ')')
      .replace(/\\\\/g, '\\');

    return text.trim();
  }

  /**
   * Attempts to read a cross-origin PDF iframe on the CDP.
   * If the iframe is cross-origin (S3), fetches the PDF via GM_xmlhttpRequest.
   */
  function tryCrossOriginPDFScan(iframeSrc, onResult) {
    if (!iframeSrc || iframeSrc.indexOf('amazonaws.com') === -1) {
      return false;
    }
    console.log('[HSC] Cross-origin PDF detected, fetching via GM_xmlhttpRequest:', iframeSrc.substring(0, 80));
    fetchAndExtractPDF(iframeSrc, function (pdfText) {
      if (pdfText.length < 20) {
        console.log('[HSC] Cross-origin PDF: insufficient text extracted (' + pdfText.length + ' chars)');
        return;
      }
      console.log('[HSC] Cross-origin PDF text extracted, length:', pdfText.length);
      var pdfMatch = match(pdfText);
      console.log('[HSC] Cross-origin PDF match:', pdfMatch.clearances.join(', ') || 'none', pdfMatch.hasCitizenship ? '+ citizenship' : '');
      onResult(pdfMatch);
    });
    return true;
  }

  // ── FlyoutScanner ──────────────────────────────────────────────────────
  /**
   * Watches for resume/details flyout panels to open and scans their content.
   * When a flyout opens, extracts text and updates badges on the associated card.
   */
  function setupFlyoutObserver() {
    var lastScannedSrc = '';
    var flyoutObserver = new MutationObserver(function (mutations) {
      var hasNewNodes = mutations.some(function (m) { return m.addedNodes.length > 0; });
      if (!hasNewNodes) return;

      var pdfIframe = document.querySelector('iframe[src*="pdfviewer"], iframe[src*="pdfjs"]');
      if (!pdfIframe) return;
      // Don't re-scan the same PDF
      if (pdfIframe.src === lastScannedSrc) return;

      clearTimeout(flyoutObserver._timer);
      flyoutObserver._timer = setTimeout(function () {
        try {
          var iframeDoc = pdfIframe.contentDocument || pdfIframe.contentWindow.document;
          if (!iframeDoc) {
            console.log('[HSC] Cannot access PDF iframe document');
            return;
          }

          // Look for PDF.js text layer inside the iframe
          var textLayers = iframeDoc.querySelectorAll('.textLayer span, [data-text-layer] span');
          var pdfText = '';
          textLayers.forEach(function (span) {
            pdfText += ' ' + (span.textContent || '');
          });

          // Also try getting text from the viewer's text content directly
          if (pdfText.trim().length < 20) {
            var viewerContainer = iframeDoc.querySelector('#viewer, .pdfViewer, #viewerContainer');
            if (viewerContainer) {
              pdfText = viewerContainer.textContent || '';
            }
          }

          pdfText = pdfText.trim();
          if (pdfText.length < 20) return;

          var flyoutMatch = match(pdfText);
          console.log('[HSC] PDF match result:', flyoutMatch.clearances.join(', ') || 'none', flyoutMatch.hasCitizenship ? '+ citizenship' : '');

          if (flyoutMatch.clearances.length === 0 && !flyoutMatch.hasCitizenship) return;

          // Find which candidate card triggered this flyout
          // Look for the currently highlighted/selected card
          var activeCard = document.querySelector('[data-test-id="resultCards-parent"].hsc-flyout-active') ||
                           findActiveCard();
          if (!activeCard) return;

          var candidateIdForFlyout = getCandidateId(activeCard);
          // Update the stored results and re-render badges for this card
          var existingResult = currentResults.get(activeCard);
          if (existingResult) {
            // Merge flyout results with existing card results
            var merged = {
              clearances: existingResult.clearances.slice(),
              hasCitizenship: existingResult.hasCitizenship || flyoutMatch.hasCitizenship,
              citizenshipKeyword: existingResult.citizenshipKeyword || flyoutMatch.citizenshipKeyword,
            };
            // Add new clearances from flyout
            for (var i = 0; i < flyoutMatch.clearances.length; i++) {
              if (merged.clearances.indexOf(flyoutMatch.clearances[i]) === -1) {
                merged.clearances.push(flyoutMatch.clearances[i]);
              }
            }
            currentResults.set(activeCard, merged);
          } else {
            currentResults.set(activeCard, flyoutMatch);
          }
          cacheResult(candidateIdForFlyout, currentResults.get(activeCard), activeCard.querySelector('[data-test-id="resultCard-name"]')?.textContent?.trim());
          renderBadges(activeCard, currentResults.get(activeCard));
          lastScannedSrc = pdfIframe.src;
          console.log('[HSC] Updated badges from flyout for:', activeCard.querySelector('[data-test-id="resultCard-name"]')?.textContent);
        } catch (err) {
          console.error('[HSC] Error scanning flyout:', err);
        }
      }, 500);
    });

    flyoutObserver.observe(document.body, { childList: true, subtree: true });
  }

  /**
   * Tries to find the candidate card that triggered the currently open flyout.
   * Looks for the most recently clicked "View resume" or "More details" button.
   */
  function findActiveCard() {
    // Check if any card has a focused/active resume button
    var activeBtn = document.querySelector('[data-test-id="resume-flyout-button"]:focus, [data-test-id="view-resume-button"]:focus');
    if (activeBtn) {
      return activeBtn.closest('[data-test-id="resultCards-parent"]');
    }
    // Fallback: look for aria-expanded buttons
    var expandedBtn = document.querySelector('[data-test-id="resume-flyout-button"][aria-expanded="true"], [data-test-id="view-resume-button"][aria-expanded="true"]');
    if (expandedBtn) {
      return expandedBtn.closest('[data-test-id="resultCards-parent"]');
    }
    return null;
  }

  // ── ScanManager ────────────────────────────────────────────────────────

  /**
   * Stores the latest scan results: Map<HTMLElement, MatchResult>.
   * Shared between scanAll() and filter click handlers.
   */
  var currentResults = new Map();

  /**
   * Current filter state held in memory for the session.
   */
  var currentFilterState = defaultFilterState();

  /**
   * Reference to the MutationObserver so we can disconnect if needed.
   */
  var observer = null;

  /**
   * Debounce timer ID for the MutationObserver callback.
   */
  var debounceTimer = null;

  /**
   * Orchestrates a full scan of all candidate cards on the page.
   * 1. Extracts all candidate data
   * 2. Matches keywords for each candidate
   * 3. Renders badges on each card
   * 4. Injects filter controls
   * 5. Restores filter state from persistence
   * 6. Applies filters
   * 7. Sets up click handlers on filter buttons
   */
  var isScanning = false;

  function scanAll() {
    if (isScanning) return;
    isScanning = true;

    // Step 1: Extract all candidate data from the DOM
    var candidates = extractAll();

    // Step 2: Match keywords and build results map
    currentResults = new Map();
    var matchCount = 0;
    for (var i = 0; i < candidates.length; i++) {
      var candidate = candidates[i];
      var candidateId = getCandidateId(candidate.cardElement);
      var combinedText = candidate.fullCardText || (candidate.resumeText + ' ' + candidate.notesText + ' ' + candidate.questionsText);
      var matchResult = match(combinedText);

      // Check cache for previously scanned results — try multiple key formats
      var cached = getCachedResult(candidateId);
      if (!cached || (cached.clearances.length === 0 && !cached.hasCitizenship)) {
        // Try name-based lookup as fallback
        var nameKey = 'name:' + candidate.candidateName;
        cached = getCachedResult(nameKey);
      }
      if (!cached || (cached.clearances.length === 0 && !cached.hasCitizenship)) {
        // Try all person: keys in cache by searching for name match
        var allCache = loadCache();
        var cacheKeys = Object.keys(allCache);
        for (var c = 0; c < cacheKeys.length; c++) {
          if (cacheKeys[c].indexOf('person:') === 0) {
            var entry = allCache[cacheKeys[c]];
            if (entry && entry.candidateName === candidate.candidateName) {
              cached = entry;
              break;
            }
          }
        }
      }
      if (cached && (cached.clearances.length > 0 || cached.hasCitizenship)) {
        // Merge cached results with current scan
        var merged = {
          clearances: cached.clearances.slice(),
          hasCitizenship: cached.hasCitizenship || matchResult.hasCitizenship,
          citizenshipKeyword: cached.citizenshipKeyword || matchResult.citizenshipKeyword,
        };
        for (var j = 0; j < matchResult.clearances.length; j++) {
          if (merged.clearances.indexOf(matchResult.clearances[j]) === -1) {
            merged.clearances.push(matchResult.clearances[j]);
          }
        }
        matchResult = merged;
      }

      currentResults.set(candidate.cardElement, matchResult);
      if (matchResult.clearances.length > 0 || matchResult.hasCitizenship) {
        matchCount++;
      }
    }
    console.log('[HSC] scanAll: ' + matchCount + ' candidates with keyword matches');

    // Step 3: Render badges for each card
    currentResults.forEach(function (matchResult, cardElement) {
      renderBadges(cardElement, matchResult);
    });

    // Step 4: Inject filter controls
    injectControls();

    // Step 5: Load filter state from persistence
    currentFilterState = loadFilterState();

    // Step 6: Apply filters and update button states
    applyFilters(currentFilterState, currentResults);
    updateFilterButtonStates(currentFilterState);

    // Step 7: Set up click handlers on filter buttons
    var clearanceBtn = document.querySelector('[data-hsc-filter="clearance"]');
    var citizenshipBtn = document.querySelector('[data-hsc-filter="citizenship"]');

    if (clearanceBtn) {
      clearanceBtn.addEventListener('click', function () {
        currentFilterState.clearanceFilterActive = !currentFilterState.clearanceFilterActive;
        saveFilterState(currentFilterState);
        applyFilters(currentFilterState, currentResults);
        updateFilterButtonStates(currentFilterState);
      });
    }

    if (citizenshipBtn) {
      citizenshipBtn.addEventListener('click', function () {
        currentFilterState.citizenshipFilterActive = !currentFilterState.citizenshipFilterActive;
        saveFilterState(currentFilterState);
        applyFilters(currentFilterState, currentResults);
        updateFilterButtonStates(currentFilterState);
      });
    }

    // Step 8: Track which card's flyout buttons are clicked
    var resumeBtns = document.querySelectorAll('[data-test-id="resume-flyout-button"], [data-test-id="view-resume-button"]');
    resumeBtns.forEach(function (btn) {
      btn.addEventListener('click', function () {
        // Mark the parent card as active for flyout scanning
        var allCards = document.querySelectorAll('[data-test-id="resultCards-parent"]');
        allCards.forEach(function (c) { c.classList.remove('hsc-flyout-active'); });
        var card = btn.closest('[data-test-id="resultCards-parent"]');
        if (card) card.classList.add('hsc-flyout-active');

        // Poll for PDF iframe content since MutationObserver can't see inside iframes
        var pollCount = 0;
        var pollInterval = setInterval(function () {
          pollCount++;
          // Stop if already scanned by flyout observer or timeout
          var activeCard = document.querySelector('[data-test-id="resultCards-parent"].hsc-flyout-active');
          if (activeCard && activeCard.querySelector('.hsc-badge-container')) {
            clearInterval(pollInterval);
            return;
          }
          if (pollCount > 20) {
            clearInterval(pollInterval);
            return;
          }
          try {
            var pdfIframe = document.querySelector('iframe[src*="pdfviewer"], iframe[src*="pdfjs"]');
            if (!pdfIframe) return;

            var iframeDoc = pdfIframe.contentDocument || pdfIframe.contentWindow.document;
            if (!iframeDoc) return;

            var textLayers = iframeDoc.querySelectorAll('.textLayer span');
            var pdfText = '';
            textLayers.forEach(function (span) {
              pdfText += ' ' + (span.textContent || '');
            });

            if (pdfText.trim().length < 20) {
              var viewerContainer = iframeDoc.querySelector('#viewer, .pdfViewer');
              if (viewerContainer) pdfText = viewerContainer.textContent || '';
            }

            pdfText = pdfText.trim();
            if (pdfText.length < 20) return; // Not ready yet

            clearInterval(pollInterval);

            var pdfMatch = match(pdfText);
            console.log('[HSC] PDF match:', pdfMatch.clearances.join(', ') || 'none', pdfMatch.hasCitizenship ? '+ citizenship' : '');

            if (pdfMatch.clearances.length === 0 && !pdfMatch.hasCitizenship) return;

            var activeCard = document.querySelector('[data-test-id="resultCards-parent"].hsc-flyout-active');
            if (!activeCard) return;

            var candidateId = getCandidateId(activeCard);
            var existingResult = currentResults.get(activeCard) || { clearances: [], hasCitizenship: false, citizenshipKeyword: null };
            var merged = {
              clearances: existingResult.clearances.slice(),
              hasCitizenship: existingResult.hasCitizenship || pdfMatch.hasCitizenship,
              citizenshipKeyword: existingResult.citizenshipKeyword || pdfMatch.citizenshipKeyword,
            };
            for (var k = 0; k < pdfMatch.clearances.length; k++) {
              if (merged.clearances.indexOf(pdfMatch.clearances[k]) === -1) {
                merged.clearances.push(pdfMatch.clearances[k]);
              }
            }
            currentResults.set(activeCard, merged);
            cacheResult(candidateId, merged, activeCard.querySelector('[data-test-id="resultCard-name"]')?.textContent?.trim());
            renderBadges(activeCard, merged);
            applyFilters(currentFilterState, currentResults);
            console.log('[HSC] Badges updated from PDF for:', activeCard.querySelector('[data-test-id="resultCard-name"]')?.textContent);
          } catch (err) {
            // iframe might not be ready yet, keep polling
          }
        }, 500);
      });
    });

    isScanning = false;
  }

  function observe() {
    // Only re-scan when the number of candidate cards changes (pagination/new search)
    var lastCardCount = document.querySelectorAll(DATA_EXTRACTOR_SELECTORS.candidateCard).length;

    observer = new MutationObserver(function () {
      if (isScanning) return;
      var currentCount = document.querySelectorAll(DATA_EXTRACTOR_SELECTORS.candidateCard).length;
      if (currentCount === lastCardCount) return;
      lastCardCount = currentCount;

      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(function () {
        try {
          console.log('[HSC] Card count changed to ' + currentCount + ', re-scanning...');
          scanAll();
        } catch (err) {
          console.error('[HSC] Error during mutation scan:', err);
        }
      }, 1000);
    });

    var obsContainer = document.querySelector(DATA_EXTRACTOR_SELECTORS.searchResultsWrapper) || document.body;
    observer.observe(obsContainer, { childList: true, subtree: true });
  }

  /**
   * Disconnects the MutationObserver and cleans up.
   */
  function disconnect() {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
  }

  // ── Export for testing ────────────────────────────────────────────────
  if (typeof window.__HSC_TEST__ !== 'undefined') {
    window.__HSC = window.__HSC || {};
    window.__HSC.isSearchResultsPage = isSearchResultsPage;
    window.__HSC.match = match;
    window.__HSC.CLEARANCE_PATTERNS = CLEARANCE_PATTERNS;
    window.__HSC.CITIZENSHIP_PATTERNS = CITIZENSHIP_PATTERNS;
    window.__HSC.extractAll = extractAll;
    window.__HSC.extractOne = extractOne;
    window.__HSC.DATA_EXTRACTOR_SELECTORS = DATA_EXTRACTOR_SELECTORS;
    window.__HSC.CLEARANCE_BADGE_CONFIG = CLEARANCE_BADGE_CONFIG;
    window.__HSC.CITIZENSHIP_BADGE_CONFIG = CITIZENSHIP_BADGE_CONFIG;
    window.__HSC.injectStyles = injectStyles;
    window.__HSC.renderBadges = renderBadges;
    window.__HSC.clearBadges = clearBadges;
    window.__HSC.injectControls = injectControls;
    window.__HSC.applyFilters = applyFilters;
    window.__HSC.updateFilterButtonStates = updateFilterButtonStates;
    window.__HSC.STORAGE_KEY = STORAGE_KEY;
    window.__HSC.saveFilterState = saveFilterState;
    window.__HSC.loadFilterState = loadFilterState;
    window.__HSC.scanAll = scanAll;
    window.__HSC.observe = observe;
    window.__HSC.disconnect = disconnect;
  }

  // ── DOM Discovery (Debug) ────────────────────────────────────────────
  /**
   * Logs information about the page DOM to help identify correct selectors.
   * Run window.__HSC_DEBUG() from the console to trigger manually.
   */
  function debugDOM() {
    console.log('[HSC DEBUG] Current URL:', window.location.href);
    console.log('[HSC DEBUG] isSearchResultsPage:', isSearchResultsPage());

    // Try to find candidate-like elements
    var selectors = [
      '[class*="candidate"]', '[class*="Candidate"]',
      '[class*="applicant"]', '[class*="Applicant"]',
      '[class*="search-result"]', '[class*="SearchResult"]',
      '[class*="result-card"]', '[class*="ResultCard"]',
      '[class*="profile"]', '[class*="Profile"]',
      'tr', 'li', '[role="row"]', '[role="listitem"]',
    ];
    console.log('[HSC DEBUG] Searching for candidate elements...');
    selectors.forEach(function (sel) {
      var els = document.querySelectorAll(sel);
      if (els.length > 0) {
        console.log('[HSC DEBUG]  ' + sel + ' → ' + els.length + ' elements found');
        if (els.length <= 5) {
          els.forEach(function (el) {
            console.log('[HSC DEBUG]    tag:', el.tagName, 'class:', el.className, 'id:', el.id);
          });
        } else {
          // Just show first 3
          for (var i = 0; i < 3; i++) {
            console.log('[HSC DEBUG]    tag:', els[i].tagName, 'class:', els[i].className, 'id:', els[i].id);
          }
          console.log('[HSC DEBUG]    ... and ' + (els.length - 3) + ' more');
        }
      }
    });

    // Log all elements with data- attributes (common in React apps)
    var dataEls = document.querySelectorAll('[data-testid], [data-test], [data-cy]');
    if (dataEls.length > 0) {
      console.log('[HSC DEBUG] Elements with data-testid/data-test/data-cy:');
      dataEls.forEach(function (el) {
        console.log('[HSC DEBUG]    tag:', el.tagName,
          'data-testid:', el.getAttribute('data-testid'),
          'data-test:', el.getAttribute('data-test'),
          'class:', el.className.substring(0, 80));
      });
    }

    // Check what the current selectors find
    console.log('[HSC DEBUG] Current selector results:');
    Object.keys(DATA_EXTRACTOR_SELECTORS).forEach(function (key) {
      var sel = DATA_EXTRACTOR_SELECTORS[key];
      var count = document.querySelectorAll(sel).length;
      console.log('[HSC DEBUG]  ' + key + ' (' + sel + ') → ' + count + ' elements');
    });
  }

  // Expose debug function globally
  window.__HSC_DEBUG = debugDOM;

  // ── Main Entry Point ──────────────────────────────────────────────────
  if (typeof window.__HSC_TEST__ === 'undefined') {
    console.log('[HSC] Script version 2.2.0 loaded');

    // Cache reset on version change
    if (GM_getValue('hsc-cache-version', '') !== 'v2.4') {
      GM_setValue('hsc-clearance-cache', '{}');
      GM_setValue('hsc-cache-version', 'v2.4');
      console.log('[HSC] Cache reset for v2.4');
    }

    injectStyles();

    var lastHandledUrl = '';
    var waitObserverRef = null;

    function handleCurrentPage() {
      var currentUrl = window.location.href;
      if (currentUrl === lastHandledUrl) return;
      lastHandledUrl = currentUrl;

      if (waitObserverRef) {
        waitObserverRef.disconnect();
        waitObserverRef = null;
      }
      disconnect();

      if (isSearchResultsPage()) {
        console.log('[HSC] Search results page:', currentUrl);

        function waitForCards() {
          var cards = document.querySelectorAll(DATA_EXTRACTOR_SELECTORS.candidateCard);
          if (cards.length > 0) {
            console.log('[HSC] Found ' + cards.length + ' cards, scanning...');
            scanAll();
            observe();
            setupFlyoutObserver();
          } else {
            waitObserverRef = new MutationObserver(function () {
              var c = document.querySelectorAll(DATA_EXTRACTOR_SELECTORS.candidateCard);
              if (c.length > 0) {
                waitObserverRef.disconnect();
                waitObserverRef = null;
                console.log('[HSC] Found ' + c.length + ' cards after waiting, scanning...');
                scanAll();
                observe();
                setupFlyoutObserver();
              }
            });
            waitObserverRef.observe(document.body, { childList: true, subtree: true });
            setTimeout(function () {
              if (waitObserverRef) { waitObserverRef.disconnect(); waitObserverRef = null; }
              observe();
              setupFlyoutObserver();
            }, 30000);
          }
        }

        setTimeout(waitForCards, 500);
      } else if (isDetailPage()) {
        console.log('[HSC] Detail page:', currentUrl);
        handleDetailPage();
      } else if (isJobDetailPage()) {
        console.log('[HSC] Job detail page:', currentUrl);
        handleJobDetailPage();
      } else if (isApplicantsPage()) {
        console.log('[HSC] Applicants page:', currentUrl);
        handleApplicantsPage();
      }
    }

    handleCurrentPage();

    // SPA navigation detection
    var lastUrl = window.location.href;
    setInterval(function () {
      if (window.location.href !== lastUrl) {
        lastUrl = window.location.href;
        console.log('[HSC] SPA navigation detected:', lastUrl);
        lastHandledUrl = '';
        setTimeout(handleCurrentPage, 500);
      }
    }, 1000);

    var origPush = history.pushState;
    var origReplace = history.replaceState;
    history.pushState = function () {
      origPush.apply(this, arguments);
      setTimeout(function () { lastHandledUrl = ''; handleCurrentPage(); }, 500);
    };
    history.replaceState = function () {
      origReplace.apply(this, arguments);
      setTimeout(function () { lastHandledUrl = ''; handleCurrentPage(); }, 500);
    };
    window.addEventListener('popstate', function () {
      setTimeout(function () { lastHandledUrl = ''; handleCurrentPage(); }, 500);
    });
  }

})();
