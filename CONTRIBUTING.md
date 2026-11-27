# Contributing to HoneySentinel

Documentation fixes, bug reports, and focused changes to the console, engine,
and analysis pipeline are welcome. Follow the [code of conduct](CODE_OF_CONDUCT.md).

## Report a problem or suggest a change

- Search [existing issues](https://github.com/mandoof1/honeypot-ui/issues) before
  opening a new one. For a bug, include the version or commit, your deployment
  type, and steps that reproduce the problem on synthetic data.
- For a feature, describe the workflow you want to improve and the outcome
  you need. Open an issue first for changes that affect the API, data formats,
  or deployment behavior so the approach can be discussed.
- For a suspected vulnerability, follow the [security policy](SECURITY.md#how-to-report).
  Keep vulnerability details out of public issues and pull requests.

## Open a pull request

1. Fork the repository and make your change on a feature branch.
2. Use the [local setup](README.md#quick-start) and
   [development commands](README.md#development) for the components you touch.
3. Run the relevant checks. For UI changes, include a screenshot or short
   recording with synthetic data when it helps reviewers.
4. Open a pull request against the default branch. Explain what changed,
   why it matters, and which checks you ran. Link an issue if one exists.

Use synthetic fixtures and remove secrets from all public attachments. Keep
`.env` files, access tokens, captured credentials, and real session records
out of commits, logs, and screenshots. If a change affects collection,
retention, or network isolation, describe the impact and update the relevant
[documentation](README.md#configuration-and-deployment).
