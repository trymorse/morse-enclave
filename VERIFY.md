# Verify the Morse enclave

## How releases are published

Each commit here is one image Morse pinned for production, exported from Morse's private monorepo with exactly the files the image build reads. A bot makes the commit and tags it with the release, such as `v2026.10.1`, or `v2026.10.5-pins-6ab5d36` for an image rebuilt with newer pins. The commit message, and the GitHub Release on newer tags, list the image's PCR0, PCR1, and PCR2. Morse does not publish its day-to-day commits. The first release here is `v2026.10.1`. [morse-pins](https://github.com/trymorse/morse-pins) also lists older prod images, `v0.6.26` to `v0.6.34`, with no source here. An entry marked `revoked: true` is an image the app no longer accepts, and an image revoked before it deployed may have no tag here.

## Rebuild notes

- Use `dev` instead of `prod` for a dev image. The version string, `rebuild` here, is not part of the image.
- The image is arm64, and both machines build the same PCRs. On x86_64, `build.sh` takes the arm64 kernel from the arm64 package of the same Nitro CLI release and checks its SHA-256. An older release's `build.sh` has no `amazonlinux_amd64=` line and builds only on arm64. To build one on x86_64, first run `docker run --privileged --rm tonistiigi/binfmt --install arm64`. The build is then slower.
- `build.sh rootfs` instead of `eif` stops after `/tmp/out/rootfs.sha256` and runs on any machine with Docker. Compare it with the `rootfs sha256` line in the tag's commit message. Older tags have no such line. Only the PCRs cover the kernel and init that `nitro-cli` adds.

## Check the running enclave

`GET https://api.trymorse.ai/v1/attestation` needs no account and returns one Nitro attestation document per running enclave, each carrying its image's PCRs. Check them the way the app does, with [uv](https://docs.astral.sh/uv/):

```sh
uv run check-enclave.py
```

It checks each document's chain to AWS's Nitro root ([Verifying the root of trust](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)), its signature, and that it is under 30 minutes old, then prints the tag each enclave runs. It exits 1 if any enclave fails or runs an image morse-pins does not list unrevoked for prod. The document's `user_data` holds the key the app seals to. The enclave makes it at start and refuses one from outside (`internal/nitro/key.go`), so only an enclave with those PCRs can open a sealed request.
