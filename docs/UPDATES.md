# Keeping upstream updates without overwriting the web adaptation

The original package remains in `h8mail/`. The interface, Vercel handler, local
companion and safety boundaries live outside that directory. `UPSTREAM.lock.json`
records the exact imported commit and the files owned by upstream. The original
BSD copyright notice and license are retained in `LICENSE`.

The prepared workflows do not run from a local folder. Nothing has been published
or connected to an account automatically. They become available only after you
choose to publish this adapted repository to GitHub and enable its Actions.

## Automatic promotion

`Sync upstream safely` checks `khast3x/h8mail`'s `master` branch once a day at
06:27 UTC, approximately 03:27 in Sao Paulo. It can also be started from GitHub's
Actions page with **Run workflow**. Your adapted repository must use `master` as
its default and Vercel production branch.

1. Check out the current production SHA without persisting Git credentials.
2. Fetch an exact upstream commit. Import only regular files under `h8mail/`
   and the unchanged `LICENSE`. Remove only upstream-owned files that the new
   snapshot deleted. Reject unsafe paths, symbolic links, junctions, case
   collisions, oversized imports and license changes.
3. Commit a candidate in the runner's isolated checkout. Install only this
   adaptation's pinned dependencies, never upstream setup scripts or requirements.
4. Run `python -m unittest discover -s tests_web`, `npm --prefix web run check`,
   `npm --prefix web test` and `npm --prefix web run build`. Verify that
   validation did not alter tracked source.
5. If every check passes, a separate job checks out the original production SHA
   and uses its trusted importer to recreate the exact tested upstream snapshot.
   It commits only the upstream package, license and lock.
6. Push using a compare-and-swap lease against the initial production SHA. If
   anyone changed `master` meanwhile, promotion fails and cannot replace their work.

The validation job has read access only. The promotion job receives GitHub's
built-in `GITHUB_TOKEN` with `contents: write`; it never executes imported
upstream code. No personal access token or Vercel token is required by this
workflow. GitHub branch rules must permit this narrowly scoped automation to push
to `master`; if they do not, the job stops with an actionable failure.

When your repository is connected to Vercel's GitHub integration, a successful
production push is the deployment trigger. GitHub suppresses additional Actions
`push` workflows for commits made with `GITHUB_TOKEN`, so this sync runs its own
checks before pushing. Vercel's Git integration processes Git pushes separately.
Private organization repositories may apply Vercel author/team access rules to
the automation bot; use a personal repository or review those permissions if a
deployment is rejected. A successful push alone is not proof that a hosted
deployment completed.

References: [Vercel GitHub deployment behavior](https://vercel.com/docs/git/vercel-for-github),
[Vercel repository and author access rules](https://vercel.com/docs/git), and
[GitHub workflow trigger rules](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).

## What the checks guarantee

Failed imports or tests cannot update production through this workflow. The
importer cannot overwrite `web/`, `api/`, `web_adapter/`, `scripts/`, workflows,
application dependency manifests or configuration. Source deletions are bounded
by the previous lock manifest, and license changes require manual review.

The checks reduce regression risk; they cannot guarantee that every future
upstream change, external service, subscription or hosted runtime will work.
Tests use offline provider fixtures and do not prove paid account access or
live service availability. Upstream remains a source-code trust dependency.

GitHub schedules can be delayed or skipped under high load. Public repositories
with no activity for 60 days can have scheduled workflows disabled automatically;
re-enable the workflow from Actions when needed. See
[GitHub's schedule limitations](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

## Manual review and recovery

If an update fails, review the failed Actions step. Existing production code is
left in place. Do not replace adapters or disable failing tests to force an
update. An upstream API or method change may require an adapter change and a
corresponding regression test. License changes require reviewing the new terms
and retaining all required original notices before updating the lock baseline.

For a manual update, start with a clean temporary worktree:

```bash
git worktree add ../H8MAIL-update -b review/upstream master
cd ../H8MAIL-update
python scripts/sync_upstream.py
python -m pip install -r requirements.txt
npm ci --prefix web
python -m unittest discover -s tests_web
npm --prefix web run check
npm --prefix web test
npm --prefix web run build
git diff -- h8mail LICENSE UPSTREAM.lock.json
```

The importer supports `--commit <complete-upstream-sha>` for reproducible review.
It only changes the checkout; it does not commit, push or deploy. Review and
publish the tested result through your normal repository process.

If a promoted change causes a problem not covered by the tests, revert its sync
commit and publish the revert. In Vercel, you can also restore a known working
deployment from the deployment history. Disable the sync workflow until the
underlying compatibility issue is fixed, otherwise the next run will try to
import the same upstream commit again.
