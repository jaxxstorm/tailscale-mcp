# Integration Attribution

The `adopt-recommended-fork-fixes` integration draws on reviewed source and concepts from [jstevewhite/tailscale-mcp](https://github.com/jstevewhite/tailscale-mcp), reviewed through commit `481c082`, rather than merging its history wholesale.

Source references for the selected build, authorization, transport, federation, and tool-catalog work are `141c42a`, `50e3a1f`, `5638692`, `641377e`, `8c018c0`, `07db451`, `a0c2d4f`, `a91bb49`, and `547fa47` / `16ba552` / `95c92ef`. These identify source concepts and patches, not an assertion that each entire commit was imported unchanged.

The integration excludes fork runtime state, keys, certificates, logs, unrelated planning documents, and wholesale Git history. It also excludes named/URL profiles and wrapper removal: existing curated wrappers, endpoint identities, schemas, and mutation confirmations remain supported. Local HTTP has a separate opt-in, and authorization, catalog ownership, and lifecycle handling follow this project's reviewed design rather than adopting all fork behavior.

Use only fresh or operator-owned tsnet state. Keep custom state paths and assertion files outside the source/build tree; default `tsnet-*` directories are ignored, Docker context is limited to Go build inputs, and release archive extras are explicitly listed documentation files. No live-tailnet validation is implied by source review or offline checks.
