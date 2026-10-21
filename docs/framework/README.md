# PTPAN framework documentation

For developers connecting a platform to PTPAN. The public `README.md` describes what PTPAN is and what to install; these pages describe how the pieces fit and what a platform implements.

1. [System map](federation-base-system-map.md): the processes at one provider, which upstream project owns each mechanism, and the paths between them.
2. [Platform wiring](raw/platform-wiring.md) (raw): everything a platform wires in. Backend RPCs, stream sockets, the data it stores, user and operator screens and fields, deployment, wire payloads, configuration and the conformance suite. This is the source for the full framework and install guides.
3. [Reference labels](labels.md): what the D-, H- and principle labels in code comments and schemas mean.

Normative sources, in order: `proto/ptpan/platform/v1/platform.proto` (the platform boundary) and `schemas/` (wire messages and vectors). Where a page here disagrees with them, they win.
