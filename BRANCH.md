# BRANCH.md — branch 6: AES67 (RTP/L24) network audio output

* Branch: `feat/aes67-network-output`
* Base: `alpha-dev` @ `1679ed7` (worktree `scratch/lead/nsp-branches/wt6-aes67`)
* Commit: see `git log -1 --format=%H` (single commit for this branch)
* Scope: standalone, **independently testable** AES67 sender + NSP integration
  design. No full NSP build was attempted (missing pinned Zig/Rust/LLVM-MinGW;
  gcc 16.1 is the only available C toolchain here).

## 1. What was built

```
tools/aes67-output/
  aes67_tx.h/.c        RTP/L24 sender, bounded f32 ring, paced thread, C ABI
  aes67_sdp.h/.c       SDP generator (L24/48k/N, ptime, ts-refclk, mediaclk)
  aes67_send.c         aes67-send.exe CLI tone generator (--dest/--channels/...)
  aes67_layouts.h      generated layout labels from contracts/output-layouts.json
  gen-layouts.py       regenerates the header (invoked by Build.ps1)
  Build.ps1            gcc -std=c11 build -> build/aes67-output/aes67-send.exe
  Test-Aes67.py        stdlib acceptance test (RTP/SDP/L24/multicast) -> out/results.json
  out/results.json     measured results (machine-readable, committed)
docs/core/aes67-output.md   architecture, wire format, SDP, PTP, latency, gaps
tools/aes67-output/INTEGRATION.md   Zig-side integration diff (not compiled)
BRANCH.md            this file
```

Design (one paragraph): the sink consumes the same `output_stream.zig` pool
leases that ASIO uses today; the owner thread pops <=4 leases per 1 ms pass,
`nsp_aes67_submit` copies them into a bounded f32 ring and returns, and a
dedicated thread converts ring data to L24 big-endian RTP packets on an
absolute QPC timeline with bounded catch-up bursts. Underruns send silence and
are counted; ring overflow drops the oldest frames and is counted. No network
I/O ever happens on the renderer or DSP path.

Key numbers: 12 ch x 48 frames x 3 B = 1728 B payload + 12 B header = 1740 B per
1 ms packet -> **13.824 Mbps payload / 13.920 Mbps on wire** at 48 kHz.

## 2. Integration points in the existing NSP tree (file:line)

| Point | Evidence |
|---|---|
| Direction bullet ("add native network-audio output") | `README.md:48-50` |
| Host chooses the output backend / creates the session | `tools/zig-scheduler/host.zig:304-326` |
| Pipeline binds the lease stream | `tools/zig-scheduler/native.zig:132-140` |
| Lease model (32 slots, 480 frames, token+release) | `tools/zig-scheduler/output_stream.zig:26-36,185-204` |
| Owner submit loop to copy/modify | `tools/zig-scheduler/asio_control.zig:169-174` |
| Session lifecycle glue to mirror | `tools/zig-scheduler/output_playback.zig:48-70` |
| Common DSP (shared, unchanged) | `tools/zig-scheduler/output_processing.zig:78-161` |
| playback JSON parsing/validation | `tools/zig-scheduler/desktop_playback.zig:31-55` |
| Layout single source | `contracts/output-layouts.json:5-13` |
| Output hand-off rationale | `docs/core/output-pool-processing-20261022.md:9-55` |

Integration proposal (details in `tools/aes67-output/INTEGRATION.md`): add
`outputBackend: "asio"|"aes67"` + a `network` block to playback.json, add
`aes67_control.zig` + `aes67_playback.zig` mirroring the ASIO pair, and reuse
`output_control.Worker(Backend)`. Lease return happens immediately after
`nsp_aes67_submit` returns because the sender copies into its own ring.

## 3. Test results (loopback + multicast, 2 s, 12 ch, 1 ms ptime, 1 kHz tone)

28 checks PASS / 0 FAIL / 0 SKIP (3 consecutive runs: 28/28, 28/28, 28/28).
Multicast smoke on `239.69.1.1`: PASS (~1000 packets/s, TTL 1).

| Case | Result | Evidence |
|---|---|---|
| sender:exit-code | PASS | exit 0 |
| loopback:packets | PASS | 2010 received vs 2000 expected (2 s @ 1 ms) |
| rtp:header | PASS | v=2, p=0, x=0, cc=0, m=0, pt=96 on all packets |
| rtp:ssrc-stable | PASS | single SSRC `0x4E535036` |
| rtp:seq-continuity | PASS | lost=0, out_of_order=0, seq 0..2009 |
| rtp:timestamp-step | PASS | every delta == 48 |
| rtp:payload-length | PASS | 1728 B = 48x12x3 for all packets |
| l24:channel-ramp-order | PASS | measured peaks 0.041667..0.5, strictly increasing (interleaving order verified) |
| l24:tone-zcr | PASS | 1990.05 crossings/s vs 2000 expected (+/-2%) |
| l24:tone-slope | PASS | max adjacent diff 0.005439 <= bound 0.005724 |
| l24:no-midstream-silence | PASS | silence only in contiguous prefix/suffix |
| stream:arrival-pacing | PASS | arrival span 2.009 s, 999.98 pkt/s measured |
| sdp:* (13 cases) | PASS | v=0, m=audio/PT96, rtpmap L24/48000/12, ptime 1, sendonly, mediaclk, ts-refclk, c=, fmtp channel-order, channel labels |
| sender:no-underrun | PASS | silent 10 (prefix/suffix only), ringDropped 0, sendErrors 0, lateTicks 0 |
| sender:pacing | PASS | stats elapsedMs 2250 (includes teardown; arrival span authoritative) |
| multicast:239.69.1.1 | PASS | 1010 packets in 1 s |

Interpretation of the two "silent" numbers: `silentPackets=10` are the very first
packets before the CLI prebuffer is consumed and the last few while the ring
drains; `l24:no-midstream-silence` proves no silent packet occurs between the
first and last non-silent packet. `stats.elapsedMs` is taken at `stop()` after
drain, so it overstates wall duration; `stream:arrival-pacing` (receiver
timestamps) is the authoritative rate measurement.

## 4. Limitations / possible false positives

* **Not integrated**: no `outputBackend` field, no Zig sink, no DLL export yet —
  `INTEGRATION.md` is a design diff, explicitly unverified (no Zig toolchain).
* **No PTP slave**: `ts-refclk` is advertised but the transmit clock is the host
  clock (QPC); `localmac` fallback is non-PTP. Real AES67 confidence requires a
  locked PTP domain.
* **Windows timer granularity**: the standalone sender relies on
  `CreateWaitableTimerEx(HIGH_RESOLUTION)` + catch-up bursts. Under heavy CPU
  load the burst bound (64 periods) can be exceeded -> `late_ticks`; audio stays
  correct only if the ring has data, otherwise silence packets appear. The test
  tolerates start/tail silence but fails on mid-stream silence.
* **Test is loopback + best-effort multicast**: no real AES67 receiver, no
  switch IGMP/PTP, no packet loss/duplication injection. Multicast may SKIP on
  hosts without multicast loopback (it passed here).
* **Tone generator only**: no file/real audio input; the CLI generates the
  sine internally, so codec/sample-rate conversion paths are untested.
* **SDP is informative on channel order**: `SMPTE2110.(71,4)` is a pragmatic
  mapping, not normative ST 2110-30 conformance.
* **Underrun semantics** are documented as "silence + counter", which is a
  product decision, not an AES67 requirement.
* `stats.bitrateKbps` in the CLI JSON uses `stop-start` wall time (includes
  drain), so it understates the nominal rate; use `payloadKbps`/nominal values
  or the receiver-measured rate.

## 5. Timing / complexity

* Wall clock for the whole branch: ~60 min (implementation + build + 3 test
  runs + docs), inside the 40-60 min band; first compile succeeded, remaining
  iterations were pacing/test-threshold fixes.
* Code size: ~700 lines C (tx 430, sdp 170, cli 380), ~360 lines Python test,
  ~250 lines docs. No third-party code, no dependencies beyond Winsock2 + gcc.
* Complexity is dominated by the pacing model (absolute QPC timeline + bounded
  catch-up) and the lease-return contract, not by AES67 itself (RTP/L24 is
  simple).

## 6. If only one branch could be chosen — why this one / why not

**Why consider it**: it is the only direction explicitly named in the project's
own README (`README.md:48-50`), it reuses the existing pool-lease/DSP design
without touching the renderer, and it gives a testable path off the single ASIO
device (Pro Audio card) that currently gates all output. It is also cheap: no
new dependencies, C11 + Winsock2 only.

**Why not (yet)**: it is an integration design plus a verified standalone
transmitter, not a working NSP output path — no Zig sink, no PTP discipline, no
real receiver validation, and AES67's value depends on a PTP-locked network and
an AES67-capable receiver that most NSP users (gaming/DVS desktop) do not have.
A user-facing product would still prefer ASIO as default; AES67 is a
pro/installation feature. So: **pick it only if network audio distribution is a
real requirement and a PTP-capable network exists; otherwise it is a
well-documented prototype, not a release blocker.**

## 7. Next steps

1. Add the DLL export (`__declspec(dllexport)` + `-shared`) and a fake-sink C
   test that drives the pool lease model exactly like `asio_control.zig`.
2. Add `outputBackend`/`network` to `playback.schema.json` + Web config page.
3. Implement `aes67_control.zig`/`aes67_playback.zig` and run the existing
   seven-layout x two-renderer matrix against the network sink (PCM compare
   before/after DSP stays unchanged).
4. Validate with a real AES67 receiver (ffmpeg `-i out.sdp` / Wireshark RTP
   analysis) on an isolated PTP-locked switch.
5. Add `st2022-7` redundancy + RTCP only after the base path is accepted.
