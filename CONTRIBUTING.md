# Contributing to SSPS

This is a review proposal. Include the affected revision/profile, the concrete
failure or interoperability case, proposed normative wording and a positive or
negative fixture. Distinguish observed implementation behavior from desired
protocol behavior; link primary sources and record their revision where possible.

Changes to script construction, signature domains, fields, event kinds or safety
gates are protocol changes. State compatibility/migration impact and preserve
recovery for already funded swaps. Do not claim wire compatibility from similarly
named endpoints. Research becomes an executable profile only after its contract,
independent implementations and relevant conformance gates are documented.

Run the checks in README. Fixtures use public fixed test keys only; never submit
live wallet seeds, keys, authorization tokens, invoices or private customer data.
Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) says, never in a
public issue. Discuss everything else in issues and pull requests.

No bLIP, NIP or BOLT allocation is claimed: the TLV types and Nostr kinds used
here are experimental values. No outside project is assumed to endorse SSPS or
to have accepted them.
