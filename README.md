# NTS clock connectivity probe

Run only in a public repository with a standard GitHub-hosted Ubuntu runner. Standard public runner minutes are free under GitHub's documented billing rules: https://docs.github.com/en/billing/concepts/product-billing/github-actions

This repository contains a generic chrony diagnostic and a five-minute bounded workflow. The probe runs for up to45 seconds plus subprocess/cleanup overhead. It downloads and extracts chrony binaries without installing or starting a system service. Its own chronyd instance uses -x to disable system-clock adjustment, -U/-u to use the invoking account, and only Cloudflare's NTS source. Provider packets are verified by chrony; this script reads chrony's diagnostics. There are no application credentials, application source, deployments, caches, or artifact uploads. Diagnostic output is public in workflow logs.

Upload these three files preserving the .github/workflows/probe.yml path into the public repository main branch. A push starts the job; it can also be run manually through Actions. The resulting log is the evidence carrier.

A successful job establishes an authenticated provider diagnostic observation only. Freshness, uncertainty, clock-gate integration, replica gates, independent qualification, and production readiness remain separate work. A failed job retains the blocker in logs. Do not interpret parser checks as actual provider observations.
