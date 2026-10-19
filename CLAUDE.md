# amit-cc-plugins

## Pushing

This repo has two remotes. `origin` is public: the marketplace installs plugins from it. `private` is the staging remote. The full process is in the Contributing section of `README.md`; use the `release` skill for every push.

- Push to `private` only, until the owner tests the change and approves it for `origin` by name. An approval to "push" is not an approval for `origin`.
- On `origin`, one commit holds one logical change, and one push carries one commit. Never combine unrelated changes to meet that rule.
- Never force-push either remote.
