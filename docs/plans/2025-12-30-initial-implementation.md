# CTI Use Case Library - Initial Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a comprehensive CTI Use Case Library with 22 tactical use cases mapped to products from the CTI Product Assessment Matrix.

**Architecture:** Documentation-based repository with category-organized markdown files, standardized templates, and direct GitHub links to product assessments.

**Tech Stack:** Markdown, Git, GitHub (GNU GPL v3 license)

---

## Phase 1: Foundation (Repository Structure & Core Documentation)

### Task 1: Create Directory Structure

**Files:**
- Create: `threat-hunting-detection/.gitkeep`
- Create: `vulnerability-intelligence/.gitkeep`
- Create: `strategic-intelligence-reporting/.gitkeep`
- Create: `templates/.gitkeep`
- Create: `.github/ISSUE_TEMPLATE/.gitkeep`

**Step 1: Create category directories**

```bash
mkdir -p threat-hunting-detection vulnerability-intelligence strategic-intelligence-reporting templates .github/ISSUE_TEMPLATE
```

**Step 2: Create .gitkeep files to track empty directories**

```bash
touch threat-hunting-detection/.gitkeep
touch vulnerability-intelligence/.gitkeep
touch strategic-intelligence-reporting/.gitkeep
touch templates/.gitkeep
touch .github/ISSUE_TEMPLATE/.gitkeep
```

**Step 3: Verify structure**

Run: `tree -L 2 -a`
Expected: Directory tree showing all folders

**Step 4: Commit**

```bash
git add threat-hunting-detection/ vulnerability-intelligence/ strategic-intelligence-reporting/ templates/ .github/
git commit -m "feat: create repository directory structure

- Add three category directories for use cases
- Add templates directory for contributor guidance
- Add GitHub issue template directory

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 2: Create LICENSE File

**Files:**
- Create: `LICENSE`

**Step 1: Write GNU GPL v3 license**

Create `LICENSE` with full GNU General Public License v3.0 text from https://www.gnu.org/licenses/gpl-3.0.txt

**Step 2: Verify license content**

Run: `head -n 5 LICENSE`
Expected: Should show GPL v3 header

**Step 3: Commit**

```bash
git add LICENSE
git commit -m "docs: add GNU GPL v3 license

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 3: Create README.md

**Files:**
- Create: `README.md`

**Step 1: Write README content**

Create comprehensive README with:
- Project title and overview
- Category descriptions
- Use case index (initially empty, will populate later)
- Quick start section
- Contributing link
- License information
- Link to CTI Product Assessment Matrix

**Step 2: Verify README renders correctly**

Run: `cat README.md | head -n 20`
Expected: Proper markdown formatting visible

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add comprehensive README

- Project overview and mission
- Category descriptions
- Placeholder for use case index
- Quick start and contributing guidance
- License and related project links

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 4: Create CONTRIBUTING.md

**Files:**
- Create: `CONTRIBUTING.md`

**Step 1: Write contribution guidelines**

Create CONTRIBUTING.md with:
- Code of conduct
- How to propose new use cases
- PR submission process
- Quality standards (must include product mapping, clear workflows)
- Issue reporting guidelines
- Contributor recognition policy

**Step 2: Verify content**

Run: `grep -i "pull request" CONTRIBUTING.md`
Expected: Should find PR submission instructions

**Step 3: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs: add contribution guidelines

- Code of conduct for contributors
- Use case proposal process
- PR and issue guidelines
- Quality standards and review criteria

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 5: Create docs/USAGE.md

**Files:**
- Create: `docs/USAGE.md`

**Step 1: Write usage guide**

Create docs/USAGE.md with:
- How to navigate the library
- How to select use cases for your environment
- How to adapt use cases to specific CTI platforms
- How to interpret product recommendations
- Integration with CTI Product Assessment Matrix

**Step 2: Verify structure**

Run: `grep "^##" docs/USAGE.md`
Expected: Should show section headers

**Step 3: Commit**

```bash
git add docs/USAGE.md
git commit -m "docs: add usage guide

- Navigation instructions
- Use case selection guidance
- Platform adaptation tips
- Product recommendation interpretation

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 6: Create docs/PRODUCT_MAPPING_GUIDE.md

**Files:**
- Create: `docs/PRODUCT_MAPPING_GUIDE.md`

**Step 1: Write product mapping methodology**

Create docs/PRODUCT_MAPPING_GUIDE.md with:
- Methodology for product recommendations
- How to evaluate products for use cases
- Understanding assessment matrix ratings
- When to consider alternative products
- Selection criteria explanation

**Step 2: Verify content**

Run: `cat docs/PRODUCT_MAPPING_GUIDE.md | wc -l`
Expected: Substantial content (100+ lines)

**Step 3: Commit**

```bash
git add docs/PRODUCT_MAPPING_GUIDE.md
git commit -m "docs: add product mapping methodology guide

- Product recommendation criteria
- Assessment matrix integration
- Evaluation guidance for practitioners

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 7: Create GitHub PR Template

**Files:**
- Create: `.github/PULL_REQUEST_TEMPLATE.md`

**Step 1: Write PR template**

Create .github/PULL_REQUEST_TEMPLATE.md with checklist:
- [ ] Use case follows template structure
- [ ] Includes product mapping with links to Assessment Matrix
- [ ] Step-by-step workflow is clear and actionable
- [ ] Prerequisites are documented
- [ ] Expected outputs are defined
- [ ] Related use cases are cross-linked
- [ ] Markdown formatting is correct

**Step 2: Verify template**

Run: `cat .github/PULL_REQUEST_TEMPLATE.md`
Expected: Checklist format visible

**Step 3: Commit**

```bash
git add .github/PULL_REQUEST_TEMPLATE.md
git commit -m "ci: add pull request template

Ensures contributors follow quality standards

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 8: Create GitHub Issue Templates

**Files:**
- Create: `.github/ISSUE_TEMPLATE/new-use-case.md`
- Create: `.github/ISSUE_TEMPLATE/improve-use-case.md`

**Step 1: Write new use case issue template**

Create .github/ISSUE_TEMPLATE/new-use-case.md with fields:
- Use case title
- Category
- Description
- Why this use case is valuable
- Suggested products

**Step 2: Write improvement issue template**

Create .github/ISSUE_TEMPLATE/improve-use-case.md with fields:
- Which use case to improve
- What improvement to make
- Justification

**Step 3: Verify templates**

Run: `ls .github/ISSUE_TEMPLATE/`
Expected: Both template files present

**Step 4: Commit**

```bash
git add .github/ISSUE_TEMPLATE/
git commit -m "ci: add GitHub issue templates

- Template for proposing new use cases
- Template for improving existing use cases

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Phase 2: Template & Example Use Cases

### Task 9: Create Use Case Template

**Files:**
- Create: `templates/use-case-template.md`

**Step 1: Write comprehensive template**

Create templates/use-case-template.md with all sections:
- Metadata (ID, Category, Difficulty, Time)
- Description & Objectives
- Prerequisites (Data Sources, Tools, Skills)
- Step-by-Step Workflow
- Recommended CTI Products (with links to Assessment Matrix)
- Expected Outputs
- Tips & Best Practices
- Related Use Cases

**Step 2: Verify template completeness**

Run: `grep "^##" templates/use-case-template.md`
Expected: All major sections listed

**Step 3: Commit**

```bash
git add templates/use-case-template.md
git commit -m "feat: add use case template

Standardized structure for all use cases:
- Metadata and prerequisites
- Step-by-step workflows
- Product mapping section
- Best practices and related use cases

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 10: Write Threat Hunting Example (UC001)

**Files:**
- Create: `threat-hunting-detection/UC001-hunt-ransomware-file-hash-pivoting.md`

**Step 1: Write complete use case**

Create threat-hunting-detection/UC001-hunt-ransomware-file-hash-pivoting.md following template:
- Track ransomware variants through hash correlation
- Map to products: Recorded Future, VirusTotal, ReversingLabs, Anomali
- Include detailed 8-10 step workflow
- Link to https://github.com/Masriyan/CTI-Product-Assesment-Matrix products

**Step 2: Verify product links**

Run: `grep "github.com/Masriyan/CTI-Product-Assesment-Matrix" threat-hunting-detection/UC001-hunt-ransomware-file-hash-pivoting.md | wc -l`
Expected: At least 3 product links

**Step 3: Remove .gitkeep**

```bash
rm threat-hunting-detection/.gitkeep
```

**Step 4: Commit**

```bash
git add threat-hunting-detection/
git commit -m "feat: add UC001 hunt ransomware using file hash pivoting

Complete example use case for threat hunting category:
- Hash correlation methodology
- Product recommendations with Assessment Matrix links
- Step-by-step workflow

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 11: Write Vulnerability Intelligence Example (UC001)

**Files:**
- Create: `vulnerability-intelligence/UC001-prioritize-cve-exploit-intelligence.md`

**Step 1: Write complete use case**

Create vulnerability-intelligence/UC001-prioritize-cve-exploit-intelligence.md:
- Threat-informed patch prioritization
- Map to products: Recorded Future, Tenable, Rapid7 Threat Command
- Include CVSS + threat context workflow
- Link to Assessment Matrix products

**Step 2: Verify workflow completeness**

Run: `grep "^###" vulnerability-intelligence/UC001-prioritize-cve-exploit-intelligence.md | wc -l`
Expected: 8-10 workflow steps

**Step 3: Remove .gitkeep**

```bash
rm vulnerability-intelligence/.gitkeep
```

**Step 4: Commit**

```bash
git add vulnerability-intelligence/
git commit -m "feat: add UC001 prioritize CVE using exploit intelligence

Complete example for vulnerability intelligence category:
- Threat-informed patching methodology
- CVSS + exploit intelligence workflow
- Product recommendations

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 12: Write Strategic Intelligence Example (UC001)

**Files:**
- Create: `strategic-intelligence-reporting/UC001-executive-threat-landscape-quarterly.md`

**Step 1: Write complete use case**

Create strategic-intelligence-reporting/UC001-executive-threat-landscape-quarterly.md:
- Quarterly board/C-suite threat briefings
- Map to products: Recorded Future, Mandiant, IBM X-Force
- Include report structure and data collection workflow
- Link to Assessment Matrix products

**Step 2: Verify content quality**

Run: `cat strategic-intelligence-reporting/UC001-executive-threat-landscape-quarterly.md | wc -w`
Expected: 800-1200 words

**Step 3: Remove .gitkeep**

```bash
rm strategic-intelligence-reporting/.gitkeep
```

**Step 4: Commit**

```bash
git add strategic-intelligence-reporting/
git commit -m "feat: add UC001 executive threat landscape quarterly report

Complete example for strategic intelligence category:
- Executive briefing structure
- Data collection and analysis workflow
- Product recommendations

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Phase 3: Complete Use Case Development

### Task 13-19: Remaining Threat Hunting Use Cases (7 more)

**Files:**
- Create: `threat-hunting-detection/UC002-track-apt-infrastructure-passive-dns.md`
- Create: `threat-hunting-detection/UC003-detect-living-off-land-techniques.md`
- Create: `threat-hunting-detection/UC004-hunt-c2-beaconing-patterns.md`
- Create: `threat-hunting-detection/UC005-identify-phishing-domain-patterns.md`
- Create: `threat-hunting-detection/UC006-detect-credential-stuffing-breach-intel.md`
- Create: `threat-hunting-detection/UC007-hunt-cve-exploitation-attempts.md`
- Create: `threat-hunting-detection/UC008-track-malware-distribution-infrastructure.md`

**For each use case:**

**Step 1: Write complete use case following template**
- Follow templates/use-case-template.md structure
- Map to appropriate products from Assessment Matrix
- Include 8-10 detailed workflow steps
- Add Tips & Best Practices section

**Step 2: Verify product mapping**

Run: `grep "github.com/Masriyan/CTI-Product-Assesment-Matrix" [file] | wc -l`
Expected: At least 2-4 product links

**Step 3: Commit individually**

```bash
git add threat-hunting-detection/UC00X-*.md
git commit -m "feat: add UC00X [use case name]

[Brief description of use case]

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 20-25: Remaining Vulnerability Intelligence Use Cases (6 more)

**Files:**
- Create: `vulnerability-intelligence/UC002-track-zero-day-exploitation-wild.md`
- Create: `vulnerability-intelligence/UC003-map-vulnerabilities-threat-actor-ttps.md`
- Create: `vulnerability-intelligence/UC004-monitor-exploit-code-releases.md`
- Create: `vulnerability-intelligence/UC005-correlate-vulnerabilities-asset-inventory.md`
- Create: `vulnerability-intelligence/UC006-track-exploit-kit-cve-integration.md`
- Create: `vulnerability-intelligence/UC007-threat-informed-patch-planning.md`

**For each use case:**

**Step 1: Write complete use case following template**

**Step 2: Verify product mapping**

Run: `grep "github.com/Masriyan/CTI-Product-Assesment-Matrix" [file] | wc -l`
Expected: At least 2-4 product links

**Step 3: Commit individually**

```bash
git add vulnerability-intelligence/UC00X-*.md
git commit -m "feat: add UC00X [use case name]

[Brief description]

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 26-31: Remaining Strategic Intelligence Use Cases (6 more)

**Files:**
- Create: `strategic-intelligence-reporting/UC002-industry-specific-threat-analysis.md`
- Create: `strategic-intelligence-reporting/UC003-threat-actor-capability-evolution.md`
- Create: `strategic-intelligence-reporting/UC004-geopolitical-threat-impact-assessment.md`
- Create: `strategic-intelligence-reporting/UC005-regulatory-compliance-threat-reporting.md`
- Create: `strategic-intelligence-reporting/UC006-threat-forecast-prediction-reporting.md`
- Create: `strategic-intelligence-reporting/UC007-annual-threat-retrospective.md`

**For each use case:**

**Step 1: Write complete use case following template**

**Step 2: Verify product mapping**

Run: `grep "github.com/Masriyan/CTI-Product-Assesment-Matrix" [file] | wc -l`
Expected: At least 2-4 product links

**Step 3: Commit individually**

```bash
git add strategic-intelligence-reporting/UC00X-*.md
git commit -m "feat: add UC00X [use case name]

[Brief description]

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Phase 4: Polish & Launch

### Task 32: Generate Use Case Index in README

**Files:**
- Modify: `README.md`

**Step 1: Create comprehensive use case index table**

Add to README.md after "## 📊 Use Case Index" section:

| ID | Use Case | Category | Difficulty | Time | Top Products |
|----|----------|----------|------------|------|--------------|
| UC001 | Hunt Ransomware Using File Hash Pivoting | Threat Hunting | Intermediate | 1-2 hours | Recorded Future, VirusTotal |
[... continue for all 22 use cases ...]

**Step 2: Verify table formatting**

Run: `grep "^|" README.md | wc -l`
Expected: 23-24 lines (header + 22 use cases)

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add complete use case index to README

Searchable table with all 22 use cases

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 33: Add Cross-Links Between Related Use Cases

**Files:**
- Modify: All 22 use case files

**Step 1: Identify related use cases**

Review each use case and identify 2-3 related/complementary use cases

**Step 2: Add "Related Use Cases" section**

For each use case, add links at the bottom:

```markdown
## Related Use Cases

- [UC002: Track APT Infrastructure Using Passive DNS](../threat-hunting-detection/UC002-track-apt-infrastructure-passive-dns.md) - Complementary infrastructure tracking
- [UC007: Hunt for CVE Exploitation Attempts](../threat-hunting-detection/UC007-hunt-cve-exploitation-attempts.md) - Vulnerability-based hunting
```

**Step 3: Verify cross-links**

Run: `grep -r "Related Use Cases" */UC*.md | wc -l`
Expected: 22 (one per use case)

**Step 4: Commit**

```bash
git add threat-hunting-detection/ vulnerability-intelligence/ strategic-intelligence-reporting/
git commit -m "feat: add cross-links between related use cases

Improves discoverability and workflow combinations

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 34: Verify All Product Links

**Files:**
- All use case files (quality check)

**Step 1: Extract all Assessment Matrix links**

Run: `grep -roh "https://github.com/Masriyan/CTI-Product-Assesment-Matrix[^)]*" */UC*.md | sort -u > /tmp/product-links.txt`

**Step 2: Verify link format**

Run: `cat /tmp/product-links.txt | wc -l`
Expected: 30-50 unique product links

**Step 3: Manual spot-check links**

Visit 5-10 random links to ensure they follow correct format:
`https://github.com/Masriyan/CTI-Product-Assesment-Matrix/blob/main/tier-X/product-name.md`

**Step 4: Fix any broken links if found**

If broken links discovered, fix and commit:

```bash
git add [affected-files]
git commit -m "fix: correct product assessment matrix links

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 35: Final Proofread and Polish

**Files:**
- All markdown files (quality check)

**Step 1: Check for markdown formatting issues**

Run: `find . -name "*.md" -type f | xargs grep -n "^#[^# ]"` (headers without space)
Expected: No results (all headers properly formatted)

**Step 2: Check for broken internal links**

Run: `grep -rn "](.*\.md)" */UC*.md docs/*.md | grep -v "github.com"`
Expected: All internal links use correct relative paths

**Step 3: Verify consistent terminology**

Check that use cases use consistent terms:
- "CTI" (not "Cyber Threat Intelligence" inconsistently)
- "Assessment Matrix" (not "Product Matrix" or variations)

**Step 4: Commit any fixes**

```bash
git add .
git commit -m "docs: final proofreading and formatting fixes

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 36: Prepare for GitHub Push

**Files:**
- Repository configuration

**Step 1: Set remote origin**

```bash
git remote add origin https://github.com/Masriyan/CTI_Usecase_Library.git
```

**Step 2: Rename branch to main**

```bash
git branch -M main
```

**Step 3: Review final commit log**

Run: `git log --oneline`
Expected: Clean, descriptive commit history

**Step 4: Final status check**

Run: `git status`
Expected: "nothing to commit, working tree clean"

---

## Summary

**Total Tasks:** 36
**Estimated Time:** 15-20 hours
**Deliverables:**
- Complete repository structure
- All documentation (README, CONTRIBUTING, USAGE, PRODUCT_MAPPING_GUIDE)
- Use case template
- 22 complete use cases with product mapping
- GitHub templates (PR, Issues)
- Ready for push to https://github.com/Masriyan/CTI_Usecase_Library

**Key Principles Applied:**
- ✅ DRY: Template reused for all use cases
- ✅ YAGNI: Only essential documentation, no over-engineering
- ✅ Frequent commits: Each task commits independently
- ✅ Product mapping: Every use case links to Assessment Matrix
- ✅ Quality: Cross-links, verification, proofread

**Post-Implementation:**
- Push to GitHub
- Configure repository settings (description, topics, website)
- Announce to CTI community
- Monitor for community contributions
