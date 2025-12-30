# Contributing to CTI Use Case Library

Thank you for your interest in contributing to the CTI Use Case Library! This project thrives on community contributions from CTI practitioners, security analysts, and threat intelligence professionals who want to share practical, actionable use cases.

## Code of Conduct

### Our Commitment

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of background, experience level, or identity. We expect all participants to:

- Be respectful and professional in all interactions
- Provide constructive feedback focused on improving use cases
- Welcome newcomers and help them get started
- Share knowledge and best practices openly
- Give credit where credit is due
- Focus on what's best for the community and CTI practitioners

### Unacceptable Behavior

The following behaviors are not tolerated:

- Harassment, discrimination, or hostile behavior
- Trolling, insulting comments, or personal attacks
- Publishing others' private information without permission
- Spam, promotional content unrelated to CTI use cases
- Any conduct that would be inappropriate in a professional setting

### Enforcement

Project maintainers have the right and responsibility to remove, edit, or reject contributions that do not align with this Code of Conduct. Repeated violations may result in being blocked from the project.

## How to Contribute

There are several ways to contribute to this library:

### 1. Propose New Use Cases

Have a practical CTI use case that would benefit the community? We'd love to include it!

**Before proposing:**
- Check existing use cases to avoid duplicates
- Ensure your use case is practical and actionable
- Have clear workflows and acceptance criteria
- Identify relevant CTI products/platforms

**To propose a new use case:**
1. Open an issue using the "New Use Case" template
2. Fill in all required fields with detailed information
3. Wait for maintainer feedback and discussion
4. If approved, you can submit a PR or request assignment

### 2. Improve Existing Use Cases

Found a way to make an existing use case better? Improvements are always welcome!

**Types of improvements we value:**
- Additional workflow steps or clarity improvements
- Better product recommendations or mappings
- Real-world implementation tips from your experience
- Updated MITRE ATT&CK mappings
- Corrected errors or outdated information
- Enhanced acceptance criteria

**To propose an improvement:**
1. Open an issue using the "Improve Use Case" template
2. Clearly explain the current state and proposed improvement
3. Provide justification for why this improves the use case
4. Wait for discussion and approval before submitting a PR

### 3. Fix Bugs or Documentation Issues

Notice a typo, broken link, or formatting issue? Small fixes are appreciated!

**For minor fixes:**
- You can submit a PR directly without opening an issue
- Clearly describe what you're fixing in the PR description
- Keep changes focused and limited to the specific fix

### 4. Share Implementation Experiences

Used a use case in production? Share your experience!

**Ways to share:**
- Add tips and lessons learned via PR to existing use cases
- Comment on use case issues with real-world feedback
- Suggest adjustments based on your platform/environment

## Pull Request Process

### Before Submitting a PR

1. Review existing PRs to avoid duplicates
2. Ensure you've opened an issue first (unless it's a minor fix)
3. Read the relevant documentation:
   - Use Case Template (coming in Phase 2) (for new use cases)
   - [Product Mapping Guide](docs/PRODUCT_MAPPING_GUIDE.md) (for product recommendations)
   - [Usage Guide](docs/USAGE.md) (for understanding library structure)

### Creating Your Pull Request

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/use-case-name`)
3. Make your changes following our quality standards (see below)
4. Test that all markdown renders correctly
5. Commit with clear, descriptive messages
6. Push to your fork
7. Open a pull request using our PR template
8. Complete all items in the PR checklist

### PR Checklist (will be in template)

Your PR should meet these requirements:

- [ ] Follows the use case template structure (if new use case)
- [ ] Includes product mapping with links to Assessment Matrix
- [ ] Step-by-step workflow is clear and actionable
- [ ] Prerequisites are fully documented
- [ ] Expected outputs are clearly defined
- [ ] Related use cases are cross-linked appropriately
- [ ] Markdown formatting is correct (headers, lists, links)
- [ ] No broken links (verify all URLs work)
- [ ] Proper grammar and professional tone
- [ ] MITRE ATT&CK mappings are accurate (if applicable)

## Quality Standards

All use cases must meet these standards to be accepted:

### 1. Product Mapping Required

Every use case MUST include product recommendations with:

- At least 2-3 recommended CTI products/platforms
- Direct links to the [CTI Product Assessment Matrix](https://github.com/Masriyan/CTI-Product-Assesment-Matrix)
- Brief explanation of why each product is recommended
- Rating context from the Assessment Matrix
- Alternative products when applicable

**Example format:**
```markdown
## Recommended CTI Products

### Primary Recommendation: Recorded Future
**Assessment Matrix:** [Tier 1 - Recorded Future](https://github.com/Masriyan/CTI-Product-Assesment-Matrix/blob/main/tier-1/recorded-future.md)

Recorded Future excels at this use case due to its comprehensive threat intelligence database and real-time correlation capabilities...
```

### 2. Clear, Actionable Workflows

Workflows must be:

- Step-by-step with numbered instructions
- Actionable by someone with prerequisite skills
- Specific enough to implement but flexible enough to adapt
- Include expected results at each major step
- Reference specific product features where relevant

### 3. Complete Documentation

Each use case must include:

- Metadata (ID, category, difficulty, estimated time)
- Clear description and objectives
- Prerequisites (data sources, tools, skills required)
- Detailed workflow (8-10+ steps for complex use cases)
- Product recommendations (see above)
- Expected outputs and acceptance criteria
- Tips and best practices
- Related use cases (cross-linking)

### 4. Professional Quality

All contributions should:

- Use professional language appropriate for security practitioners
- Follow markdown best practices
- Have no spelling or grammatical errors
- Use consistent terminology throughout
- Be well-organized and easy to navigate

### 5. Practical and Tested

Use cases should be:

- Based on real-world implementation or established practices
- Practical to implement in typical CTI environments
- Valuable to other CTI practitioners
- Tested or validated where possible

## Issue Reporting Guidelines

### When Opening Issues

**Good issues include:**
- Clear, descriptive title
- Detailed description of the proposal or problem
- Context and justification
- Relevant examples or references
- Suggested solutions (if applicable)

**Issue templates:**
- Use "New Use Case" template for proposing additions
- Use "Improve Use Case" template for suggesting changes
- Use standard issue format for bugs or questions

### Response Expectations

- Maintainers will respond to issues within 3-5 business days
- Complex proposals may require community discussion
- Not all proposals will be accepted (see acceptance criteria)
- Constructive feedback will be provided for rejected proposals

## Use Case Acceptance Criteria

For a use case to be accepted, it must:

1. **Be Valuable**: Addresses a real CTI need or common scenario
2. **Be Practical**: Can be implemented by CTI teams in real environments
3. **Be Complete**: Includes all required template sections
4. **Have Product Mapping**: Links to at least 2 relevant products in Assessment Matrix
5. **Be Unique**: Doesn't duplicate existing use cases (or significantly extends them)
6. **Meet Quality Standards**: Professional writing, correct formatting, no errors
7. **Be Actionable**: Clear workflows that practitioners can follow

## Contributor Recognition

We value and recognize all contributors!

### Recognition Methods

- All contributors are listed in commit history
- Significant contributors may be recognized in README acknowledgments
- Contributors retain credit for their specific use cases
- Community contributors may be invited to maintainer roles

### Attribution

When contributing:
- You retain copyright of your original work
- By contributing, you agree to license your work under the project's GNU GPL v3 license
- You affirm that your contribution is your original work or properly attributed
- If adapting existing methodology, provide appropriate attribution

## Getting Help

Need help contributing?

- Review existing use cases for examples
- Check the [Usage Guide](docs/USAGE.md) for library navigation
- Check the [Product Mapping Guide](docs/PRODUCT_MAPPING_GUIDE.md) for product recommendation help
- Open an issue with your question
- Reach out to maintainers via GitHub discussions

## Development Process

### Branch Strategy

- `main` branch contains stable, reviewed use cases
- Feature branches for new use cases: `feature/uc-XXX-name`
- Improvement branches: `improve/uc-XXX-description`
- Documentation branches: `docs/description`

### Review Process

1. Maintainer reviews PR for completeness
2. Technical review for accuracy and quality
3. Product mapping verification
4. Community feedback period (for major additions)
5. Final approval and merge
6. README index update (if needed)

### Versioning

- Use cases use semantic versioning (major.minor.patch)
- Breaking changes to workflows = major version bump
- New steps or improvements = minor version bump
- Corrections or clarifications = patch version bump
- Version noted in use case metadata

## Questions?

If you have questions not covered here:
- Check existing documentation in `/docs`
- Search existing issues and discussions
- Open a new issue with your question

Thank you for helping make CTI more accessible and practical for the security community!
