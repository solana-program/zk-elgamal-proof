# Security Policy

## Reporting a Vulnerability

We take the security of our projects seriously. To ensure vulnerabilities are
handled securely, **please do not report security issues through public GitHub issues.**

Instead, please use GitHub's private vulnerability reporting feature.

- For vulnerabilities in the **`zk-sdk`**, report them via the **Agave repository**:
  - [Report `zk-sdk` Vulnerability](https://github.com/anza-xyz/agave/security/advisories/new)
- For all **other components** in this repository, use the following link:
  - [Report Other Vulnerability](https://github.com/solana-program/zk-elgamal-proof/security/advisories/new)

When reporting, please provide a clear title and a detailed description of the
issue. To protect your account, we also recommend **enabling two-factor authentication**
on GitHub. You can typically expect an initial response to your advisory within
72 hours.

--

If you do not receive a response in the advisory, send an email to
<security@anza.xyz> with the full URL of the advisory you have created. DO NOT
include attachments or provide detail sufficient for exploitation regarding the
security issue in this email. **Only provide such details in the advisory**.

If you do not receive a response from <security@anza.xyz> please followup with
the team directly. You can do this in one of the `#Dev Tooling` channels of the
[Solana Tech discord server](https://solana.com/discord), by pinging the admins
in the channel and referencing the fact that you submitted a security problem.

## Security Bug Bounties

The Solana Foundation offers bounties for critical security issues. Please
see the [Agave Security Bug
Bounties](https://github.com/anza-xyz/agave/security/policy#security-bug-bounties)
for details on classes of bugs and payment amounts.

## Scope

For the purposes of the bug bounty program, only vulnerabilities in the
**`zk-sdk`** that affect the agave validator client are considered in scope.

We still encourage the responsible disclosure of vulnerabilities found in other
components of this repository, even if they do not qualify for a bounty.
