# Release Checklist

## Current Verified State (2026-09-30)

- Public repository: https://github.com/LMK-ai-nb/permscope (`main`).
- Published package: https://mooncakes.io/docs/LMK-ai-nb/permscope@0.1.1.
- `0.1.2` is a local September release candidate, not a published package.

## Before Publishing 0.1.2

- [ ] Confirm the September changes are committed to the existing Git history
      by 李明坤 / `LMK-ai-nb` and pushed to the default branch.
- [ ] Confirm GitHub Actions passed for the exact release commit.
- [ ] Run `moon fmt --check`, `moon check --deny-warn`, `moon build`,
      `moon test --deny-warn`, `moon info`, and both `moon run` examples.
- [ ] Review `moon.mod`, README, license, provenance, changelog, and generated
      public interface diff.
- [ ] Run `moon package --list` and inspect the listed files for private data,
      temporary files, and missing documentation.
- [ ] Run `moon whoami` and confirm it prints `LMK-ai-nb` before any publish
      command. The September 30 local session was authenticated as a different
      account, and a dry-run publish returned HTTP 403 User mismatch.
- [ ] Use the authorized `LMK-ai-nb` Mooncakes account to run
      `moon publish --frozen`.
- [ ] Open the exact `0.1.2` Mooncakes page and verify its package metadata.
- [ ] Record the release commit, CI run, publication result, and page link.

The registration form and event result are controlled by the organizers;
local checks cannot confirm initial review or guarantee an award.

## September Submission

- [ ] Use the community maintenance track and the one-page
      `docs/SEPTEMBER_APPLICATION.md`, with the public repository URL.
- [ ] Confirm the official form's current deadline and receipt. The official
      event page listed September 30 for this round when checked on that date.
- [ ] Before submitting or changing the form, verify the applicant is 李明坤
      and the GitHub account is `LMK-ai-nb`.
- [ ] When editing a previously submitted form, fill the "推荐人" field with
      "无" or another nonempty value if the form requires it, per the event
      notice supplied by the applicant.
- [ ] Join the official event group if required for award distribution.
