# CTI Use Case Library - Usage Guide

This guide will help you navigate the CTI Use Case Library, select appropriate use cases for your environment, and adapt them to your specific CTI platforms and tools.

## Table of Contents

- [Quick Start](#quick-start)
- [Navigating the Library](#navigating-the-library)
- [Selecting Use Cases](#selecting-use-cases)
- [Understanding Use Case Structure](#understanding-use-case-structure)
- [Adapting Use Cases to Your Environment](#adapting-use-cases-to-your-environment)
- [Working with Product Recommendations](#working-with-product-recommendations)
- [Using the CTI Product Assessment Matrix](#using-the-cti-product-assessment-matrix)
- [Implementation Best Practices](#implementation-best-practices)
- [Measuring Success](#measuring-success)

## Quick Start

### For CTI Analysts

If you're a CTI analyst looking to implement a specific capability:

1. **Identify your objective** - What problem are you trying to solve?
2. **Browse the relevant category** - Threat Hunting, Vulnerability Intelligence, or Strategic Intelligence
3. **Select a matching use case** - Read the description and objectives
4. **Review prerequisites** - Ensure you have required data sources, tools, and skills
5. **Follow the workflow** - Implement step-by-step
6. **Measure results** - Check your outputs against acceptance criteria

### For Security Leaders

If you're evaluating CTI capabilities or planning implementations:

1. **Review the use case index** in README.md for an overview
2. **Assess team readiness** - Check prerequisites and skill requirements
3. **Evaluate tooling needs** - Review product recommendations and Assessment Matrix
4. **Prioritize use cases** - Select high-value use cases aligned with organizational risk
5. **Plan implementation** - Use workflows to scope effort and resources

### For Tool Evaluators

If you're selecting or evaluating CTI platforms:

1. **Identify key use cases** for your organization
2. **Review product recommendations** in each relevant use case
3. **Cross-reference the [CTI Product Assessment Matrix](https://github.com/Masriyan/CTI-Product-Assesment-Matrix)**
4. **Map platform capabilities** to use case requirements
5. **Test workflows** during product trials or proof-of-concept

## Navigating the Library

### Repository Structure

```
CTI-Use-Case-Library/
├── README.md                              # Project overview and use case index
├── CONTRIBUTING.md                        # Contribution guidelines
├── LICENSE                                # GNU GPL v3 license
├── templates/                             # Templates for contributors
│   └── use-case-template.md
├── docs/                                  # Additional documentation
│   ├── USAGE.md                           # This file
│   └── PRODUCT_MAPPING_GUIDE.md           # Product selection methodology
├── threat-hunting-detection/              # Threat hunting use cases
│   ├── UC001-hunt-ransomware-file-hash-pivoting.md
│   ├── UC002-track-apt-infrastructure-passive-dns.md
│   └── ...
├── vulnerability-intelligence/            # Vulnerability intelligence use cases
│   ├── UC001-prioritize-cve-exploit-intelligence.md
│   ├── UC002-track-zero-day-exploitation-wild.md
│   └── ...
└── strategic-intelligence-reporting/      # Strategic intelligence use cases
    ├── UC001-executive-threat-landscape-quarterly.md
    ├── UC002-industry-specific-threat-analysis.md
    └── ...
```

### Category Descriptions

**Threat Hunting & Detection** (`threat-hunting-detection/`)
- Focus: Proactive threat identification and detection development
- Audience: Threat hunters, detection engineers, SOC analysts
- Outputs: IOCs, detection rules, investigation findings, threat patterns

**Vulnerability Intelligence** (`vulnerability-intelligence/`)
- Focus: Threat-informed vulnerability management and prioritization
- Audience: Vulnerability management teams, security engineers, risk analysts
- Outputs: Prioritized patch lists, exploitation intelligence, risk assessments

**Strategic Intelligence & Reporting** (`strategic-intelligence-reporting/`)
- Focus: Executive reporting and strategic threat analysis
- Audience: CTI analysts, security leaders, risk managers
- Outputs: Executive briefings, threat forecasts, industry analysis, risk reports

### Use Case Naming Convention

Use cases follow this pattern: `UCXXX-description-with-dashes.md`

- `UC` = Use Case prefix
- `XXX` = Sequential number within category (001, 002, etc.)
- `description` = Brief, hyphenated description of the use case

Example: `UC001-hunt-ransomware-file-hash-pivoting.md`

## Selecting Use Cases

### Selection Criteria

When choosing use cases to implement, consider:

#### 1. Organizational Needs
- What are your current security priorities?
- Which threats are most relevant to your industry/organization?
- What capabilities are you lacking or trying to improve?

#### 2. Resource Availability
- **Data Sources**: Do you have the required threat intelligence feeds, logs, or data?
- **Tools**: Do you have access to recommended CTI platforms (or alternatives)?
- **Skills**: Does your team have the prerequisite knowledge and experience?
- **Time**: Can you allocate the estimated time required?

#### 3. Maturity Level
Use cases include difficulty ratings:
- **Beginner**: Minimal CTI experience required, straightforward workflows
- **Intermediate**: Some CTI experience needed, moderate complexity
- **Advanced**: Significant CTI expertise required, complex analysis

Start with use cases matching your team's current capabilities.

#### 4. Dependencies
Some use cases build on others. Check:
- Prerequisites section for required foundational knowledge
- Related use cases section for complementary workflows
- Data requirements that may depend on other processes

### Use Case Filtering

**By Threat Type:**
- Ransomware, APT, Malware, Phishing → `threat-hunting-detection/`
- CVEs, Exploits, Vulnerabilities → `vulnerability-intelligence/`
- Geopolitical, Industry, Actor Trends → `strategic-intelligence-reporting/`

**By Time Commitment:**
- Quick wins (< 2 hours): Look for beginner-level use cases
- Regular operations (2-8 hours): Intermediate recurring workflows
- Deep analysis (8+ hours): Advanced investigations and reports

**By Output Type:**
- Need detection rules? → Threat hunting category
- Need patch priorities? → Vulnerability intelligence category
- Need executive briefings? → Strategic intelligence category

## Understanding Use Case Structure

Every use case follows a standardized template with these sections:

### Metadata
- **Use Case ID**: Unique identifier
- **Category**: Which discipline (Threat Hunting, Vuln Intel, Strategic)
- **Difficulty**: Beginner, Intermediate, or Advanced
- **Estimated Time**: How long to complete
- **Last Updated**: When use case was last reviewed

### Core Sections

1. **Description**: What the use case accomplishes and why it matters
2. **Objectives**: Specific, measurable goals
3. **Prerequisites**: Required data, tools, and skills
4. **Workflow**: Step-by-step implementation instructions
5. **Recommended CTI Products**: Platform suggestions with Assessment Matrix links
6. **Expected Outputs**: What you should produce
7. **Acceptance Criteria**: How to validate success
8. **Tips & Best Practices**: Expert guidance and common pitfalls
9. **Related Use Cases**: Links to complementary workflows

### Reading the Workflow Section

Workflows are written as sequential steps:

**Step format:**
```markdown
### Step X: [Action to Take]

**Objective**: What this step accomplishes

**Instructions**:
1. Specific action to perform
2. Expected result or output
3. Decision point or next action

**Example**: [Product-specific example when helpful]
```

**How to use:**
- Read through the entire workflow before starting
- Gather all prerequisites first
- Follow steps sequentially
- Document your results at each major step
- Adjust for your specific environment as needed

## Adapting Use Cases to Your Environment

### Platform Translation

Use cases reference specific CTI platforms, but workflows can be adapted:

#### If You Have the Recommended Product:
- Follow workflow as written
- Reference platform-specific features mentioned
- Consult product documentation for detailed instructions

#### If You Have an Alternative Product:
1. Identify equivalent capabilities in your platform
2. Map workflow steps to your product's features
3. Adjust queries, searches, or API calls to your platform's syntax
4. Test adapted workflow in non-production first

**Example Translation:**

Original step (for Recorded Future):
> "Search the Threat Intelligence database for the IP address and pivot to related infrastructure"

Adapted for VirusTotal:
> "Search VirusTotal for the IP address, then use the 'Relations' tab to pivot to associated domains and files"

Adapted for MISP:
> "Query MISP for events containing the IP, then use correlation features to find related indicators"

### Data Source Substitution

If you don't have a specific data source mentioned:

**Identify alternatives:**
- Commercial feed → Open source alternatives (OSINT, public feeds)
- Specific vendor → Equivalent capability from your vendors
- External data → Internal logs or data with similar context

**Adjust confidence levels:**
- Using fewer sources → Lower confidence in findings
- Different source quality → Adjust validation requirements
- Missing enrichment → May need manual analysis

### Skill Requirements

If your team lacks specific skills:

**Build gradually:**
- Start with beginner use cases to build knowledge
- Use related use cases as training material
- Document your learning and create internal guides

**Leverage expertise:**
- Partner with other teams (SOC, threat intel vendors, etc.)
- Use managed services for complex analysis
- Engage community resources and forums

## Working with Product Recommendations

### Understanding Recommendations

Each use case includes a "Recommended CTI Products" section with:

**Primary Recommendations:**
- Products best suited for the use case
- Links to detailed assessments in the CTI Product Assessment Matrix
- Explanation of why the product excels for this workflow

**Alternative Options:**
- Other viable products for the use case
- Trade-offs or considerations
- When to choose alternatives

**Rating Context:**
- Assessment Matrix tier (Tier 1 = comprehensive, Tier 2 = specialized, Tier 3 = niche)
- Relevant capability scores
- Strengths and limitations for this specific use case

### Interpreting Recommendations

**"Recommended: [Product]"** means:
- Product has strong capabilities for this use case
- Assessed and rated in the Assessment Matrix
- Actively used by CTI practitioners for this purpose

**"Alternative: [Product]"** means:
- Product can accomplish the use case
- May have trade-offs (cost, complexity, feature coverage)
- Consider based on your specific needs

**"Avoid"** or not listed:
- Product lacks key capabilities for this use case
- Better options available
- May still work but not optimal

### When Product Recommendations Don't Match Your Stack

**You already have a different product:**
1. Check if your product is listed as an alternative
2. Review your product's assessment in the Matrix
3. Identify capability gaps for this use case
4. Adapt workflow to work within your product's strengths
5. Consider supplemental tools for gaps

**You're evaluating products:**
1. Use recommendations as a starting point
2. Review Assessment Matrix for detailed comparisons
3. Test recommended products with use case workflows
4. Validate that workflows work as described
5. Make decisions based on your full requirements (not just one use case)

**You don't have any recommended products:**
- Look for open-source or free alternatives in Assessment Matrix
- Combine multiple simpler tools to replicate capability
- Use manual processes as temporary solution
- Document gaps for future tooling investments

## Using the CTI Product Assessment Matrix

The [CTI Product Assessment Matrix](https://github.com/Masriyan/CTI-Product-Assesment-Matrix) is a companion resource that provides detailed evaluations of CTI platforms.

### How Use Cases and Matrix Work Together

**Use Cases → Matrix:**
- Use cases reference specific products
- Links lead to detailed product assessments
- Helps you understand why products are recommended

**Matrix → Use Cases:**
- Product assessments reference applicable use cases
- Shows what you can accomplish with each product
- Validates product capabilities with real workflows

### Leveraging the Matrix

**For product evaluation:**
1. Identify key use cases you need to implement
2. Follow product links to Assessment Matrix
3. Review capability scores relevant to those use cases
4. Compare alternatives based on your priorities
5. Reference use case workflows during trials

**For implementation planning:**
1. Review your current product's assessment
2. Identify which use cases it supports well
3. Find gaps where alternative products excel
4. Plan implementation strategy based on product strengths

**For capability development:**
1. Use Matrix to understand product roadmaps
2. Identify emerging capabilities
3. Plan future use case implementations
4. Justify tooling investments with use case value

## Implementation Best Practices

### Before You Start

1. **Read the entire use case** - Don't start until you understand the full workflow
2. **Verify prerequisites** - Ensure you have all required data, tools, and access
3. **Set up documentation** - Prepare to capture results, findings, and lessons learned
4. **Allocate time** - Block sufficient time based on estimated duration
5. **Identify stakeholders** - Know who needs results and in what format

### During Implementation

1. **Follow workflows sequentially** - Don't skip steps unless you understand implications
2. **Document as you go** - Capture queries, results, decisions, and deviations
3. **Validate incrementally** - Check outputs at each major step before proceeding
4. **Note adaptations** - Record how you modified steps for your environment
5. **Track challenges** - Document issues for future iterations or contributions

### After Implementation

1. **Review acceptance criteria** - Validate that outputs meet quality standards
2. **Assess value** - Did the use case deliver expected value?
3. **Document lessons learned** - What worked? What would you change?
4. **Share findings** - Brief stakeholders, update runbooks, share with team
5. **Plan iteration** - Schedule next run, identify improvements, automate where possible

### Building Operational Workflows

**One-time use cases:**
- Deep investigations, special projects
- Follow workflow as-is
- Document findings thoroughly

**Recurring use cases:**
- Regular reporting, continuous monitoring
- Create runbooks based on workflows
- Automate repetitive steps
- Build templates for outputs
- Schedule regular execution

**Scaling use cases:**
- Start manual, understand the process
- Identify automation opportunities
- Script or automate data collection
- Template analysis and reporting
- Monitor for changes that require manual review

## Measuring Success

### Output Validation

Check your outputs against the use case's **Expected Outputs** and **Acceptance Criteria**:

**Expected Outputs** define what you should produce:
- Reports, lists, alerts, intelligence products
- Format and structure requirements
- Minimum quality thresholds

**Acceptance Criteria** define success metrics:
- Completeness (did you cover all required elements?)
- Accuracy (are findings validated and correct?)
- Timeliness (did you meet time requirements?)
- Actionability (can stakeholders act on outputs?)

### Value Assessment

Evaluate the use case's value to your organization:

**Immediate value:**
- Did you discover new threats or vulnerabilities?
- Did you prevent or mitigate security incidents?
- Did you improve detection or response capabilities?
- Did you provide actionable intelligence to stakeholders?

**Long-term value:**
- Can you repeat this use case for ongoing value?
- Did you build new skills or capabilities?
- Did you identify process improvements?
- Can you scale or automate this workflow?

### Continuous Improvement

**After each implementation:**
1. Review what worked and what didn't
2. Identify steps that could be optimized
3. Note product features that were particularly helpful
4. Consider contributing improvements back to the library

**Share your experience:**
- Add tips to use cases via pull requests
- Report issues or suggest improvements
- Share implementation experiences with the community
- Help others by documenting your lessons learned

## Getting Help

### Troubleshooting

**If a workflow step isn't clear:**
- Check related use cases for similar steps
- Review product documentation for platform-specific details
- Search for public examples of similar analysis
- Open an issue asking for clarification

**If you can't complete a use case:**
- Review prerequisites - you may be missing required data or access
- Check if you need to adapt steps for your environment
- Consider starting with a simpler related use case first
- Ask for help via GitHub issues

**If results don't match expectations:**
- Verify input data quality and completeness
- Double-check each workflow step was completed correctly
- Consider environmental differences (different threat landscape, data sources)
- Review acceptance criteria - you may have still succeeded with different results

### Community Resources

- **GitHub Issues**: Ask questions or report problems
- **Contributing Guide**: Learn how to improve use cases
- **Product Assessment Matrix**: Detailed product information
- **CTI Community**: Broader threat intelligence resources and forums

## Next Steps

Now that you understand how to use the library:

1. Browse the [use case index](../README.md#use-case-index) in the README
2. Select a use case aligned with your needs
3. Review the [Product Mapping Guide](PRODUCT_MAPPING_GUIDE.md) for product selection help
4. Implement your first use case following the workflow
5. Share your experience and contribute improvements

Welcome to the CTI Use Case Library community!
