# Release Checklist

## Current Verified State (2026-09-30)

- Published package: https://mooncakes.io/docs/LMK-ai-nb/permscope@0.1.3.
- Release source commit: `a4b0032abce9d76d11646c5d4ea3a90a24ad52f9`
  on the public `main` branch.
- GitHub Actions run: https://github.com/LMK-ai-nb/permscope/actions/runs/36734983284
  (success for the release source commit).
- `moon whoami` returned `Logged in as LMK-ai-nb` immediately before
  `moon publish --frozen`; the publish command returned `Server status: 200 OK`.
- Mooncakes manifest reports `0.1.3` as latest with `build_status: success`.
  Its package README no longer contains the outdated release and install text.

## Verified 0.1.2 Release (2026-09-30)

- Public repository: https://github.com/LMK-ai-nb/permscope (`main`).
- Published package: https://mooncakes.io/docs/LMK-ai-nb/permscope@0.1.2.
- Release source commit: `18e63752af0a79d7d92f00041a1a0faa75c09b6b`.
- GitHub Actions run: https://github.com/LMK-ai-nb/permscope/actions/runs/36718051973
  (success for the release source commit).
- Mooncakes manifest reported `0.1.2` as latest at publication, with
  `build_status: success`.

## 0.1.2 Publication Record

- [x] Confirm the September changes are committed to the existing Git history
      by 李明坤 / `LMK-ai-nb` and pushed to the default branch.
- [x] Confirm GitHub Actions passed for the exact release source commit.
- [x] Run `moon fmt --check`, `moon check --deny-warn`, `moon build`,
      `moon test --deny-warn`, `moon info`, and both `moon run` examples.
- [x] Review `moon.mod`, README, license, provenance, changelog, and generated
      public interface diff.
- [x] Run `moon package --list` and inspect the listed files for private data,
      temporary files, and missing documentation.
- [x] Run `moon whoami` and confirm it prints `LMK-ai-nb` before any publish
      command. An earlier local dry run under a different account returned
      HTTP 403; that attempt did not publish anything.
- [x] Use the authorized `LMK-ai-nb` Mooncakes account to run
      `moon publish --frozen`.
- [x] Open the exact `0.1.2` Mooncakes page and verify its package metadata.
- [x] Record the release source commit, CI run, publication result, and page link.

`moon publish --frozen` returned `Server status: 200 OK` on 2026-09-30.
The registry manifest confirmed the module name, version, repository, license,
latest-version status at publication, and successful package build.

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
