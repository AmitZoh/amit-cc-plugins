---
name: release
description: Push changes in this repo — stage them on the private remote, then release owner-approved changes to the public origin one commit at a time. Use for every push in amit-cc-plugins, including "push it", "push the commits", "ship this", or "release to origin".
---

# Release

This repo has two remotes:

- `private` — the staging remote. Every change goes here first.
- `origin` — public. The marketplace installs plugins from it, so a commit on `origin` reaches users.

The two `main` branches have different histories: `private` keeps the work-in-progress commits, and `origin` gets one squashed commit per change. Their trees match once every staged change is released.

A change moves through four steps: stage, test, approve, release. This skill does stage and release. The owner does test and approve.

## Rules

- An approval to "push" means push to `private`. Release to `origin` only when the owner approves that change for `origin` by name.
- On `origin`, one commit holds one logical change, and one push carries one commit. Never merge unrelated changes into one commit to meet that rule.
- Never force-push. If a push is refused as non-fast-forward, stop, fetch, and report.
- Chain each multi-step git command with `|| exit 1`, so a failed step stops the script. (`git cherry-pick` has no `-q` flag.)

## Stage

1. Run `git fetch --multiple private origin`.
2. Put the change's commits on top of `private/main`. If they are on another base, cherry-pick them onto a temporary branch made from `private/main`. On a conflict, run `git cherry-pick --abort` and report.
3. Tell the owner which commits go to `private`, and get approval to push them.
4. Run `git push private <branch>:main`.
5. Report the staged commits and what the owner should test. Say that `origin` did not change.

## Release

Do this only for a change the owner approved for `origin`.

1. Run `git fetch --multiple private origin`. Confirm that the change's commits are on `private/main`.
2. Make a temporary branch from `origin/main`.
3. Run `git cherry-pick --no-commit <the change's staging commits>`, oldest first. Commit the result as one commit. Use the repo's message style: one `type: description` line per logical part, for example a `fix:` line and its `chore: bump` line.
4. Show the commit to the owner, then run `git push origin <branch>:main`.
5. To release several changes, repeat steps 2–4 for each change, oldest first, one push per commit.
6. When no staged change is left unreleased, run `git diff private/main origin/main`. Expect no output; report any difference.
7. Run `git switch main && git merge --ff-only origin/main`, then delete the temporary branches.
