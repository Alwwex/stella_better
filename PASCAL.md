# GeForce GTX 10 series (Pascal) support

This fork lets Stela's Metal driver run on NVIDIA's Pascal GPUs: the
GeForce GTX 1050 to 1080 Ti, the Titan X and Xp, and the Quadro P-series
built on the same chips. It is experimental and has not run on real
hardware yet. The target card is the **GTX 1080 (GP104, PCI ID `10de:1b80`)**.

## Supported chips

| Chip | Cards |
|---|---|
| GP102 | GTX 1080 Ti, Titan X (Pascal), Titan Xp, Quadro P6000 |
| GP104 | GTX 1080, GTX 1070, GTX 1070 Ti, some GTX 1060, Quadro P4000/P5000 |
| GP106 | GTX 1060, Quadro P2000 |
| GP107 | GTX 1050, GTX 1050 Ti, Quadro P400 to P1000 |

Not supported: GP108 (GT 1030, MX150), which nouveau boots with a different
secure-boot path; GP100; and Maxwell and Volta cards.

## What to expect

- **It is slow.** nouveau cannot change a Pascal GPU's clocks, because NVIDIA
  never released the signed firmware it would need. The card runs at the
  clocks its VBIOS boots it with, far below its rated speed.
- **Metal families: Apple1 to Apple5, Common1 to Common3, Mac1 and Mac2.**
  Pascal has no mesh shaders, which Metal3 needs, and no sparse residency
  feedback (Volta and later), which Apple6 needs. Apple7 needs both plus
  barycentric coordinates (Turing and later). Turing and newer cards get
  Apple7 and Metal3. Every Mac that runs macOS 27 has an Apple7 GPU, so parts
  of macOS or apps that assume Apple7 may fail on this card. Apple3, which
  the window server's surfaces need, is reached.
- **`half` math runs in 32 bits.** Pascal has no fast 16-bit float arithmetic,
  and NVK does not report `shaderFloat16` below SM 7.0. NAK, NVK's shader
  compiler, already lowers every 16-bit float operation to 32 bits on these
  GPUs and rounds each result back to 16 bits. That matches native `half`
  exactly for add, subtract, multiply, divide and square root. This fork lets
  the Metal device use that lowering instead of refusing the GPU.
- **No host image copies.** Textures the CPU reads or writes go through a
  staging copy on the GPU. Shared or managed textures in Apple's
  extended-range formats (`BGR10_XR` and similar, used for EDR/HDR) cannot be
  created.

## How Pascal starts, compared with Turing and later

Turing and later GPUs run NVIDIA's GSP-RM firmware, which nouveau drives.
Pascal has no GSP, so the start differs:

1. Stela resets the GPU when it claims it. A GTX 1080 has no Function Level
   Reset, so this is normally a Secondary Bus Reset of the PCIe port above it.
2. After the reset the GPU is un-POSTed. nouveau sees this (register
   `0x2240c`) and runs the VBIOS's devinit program on the GPU's PMU
   (`gm200_devinit_post`), as it does for any secondary card.
3. nouveau loads linux-firmware's signed images through the ACR on the SEC2
   falcon and starts the graphics engine (FECS and GPCCS) with them.
4. NVK (Mesa 26.2.5) treats Pascal as conformant and reports Vulkan 1.3.

## What changed in this fork

| Area | Change |
|---|---|
| `stela-driver-gpu/src/nouveau_chip.rs` | New `PASCAL` chip table (GP102, GP104, GP106, GP107) and `Architecture::Pascal`; `Chip::find` searches it. |
| `stela-driver-gpu/src/metal/nvidia.rs` | The Metal admission accepts the Pascal chips; other pre-Turing chips are still refused. |
| `stela-driver-gpu/src/metal/vulkan/*`, `metal/native*` | `shaderFloat16` is satisfied when the driver lowers 16-bit float math itself (`Driver::float16_lowered`, true for NVK). |
| `stela-loader/src/host_firmware/recipes.rs` | 40 pinned linux-firmware files for Pascal (ACR, SEC2, GR, VPR scrubber) at the same revision and SHA-256-checked like the GSP files; PCI ID ranges for GP102 to GP107; `require_nouveau` chooses GSP or Pascal files. |
| `stela-loader/src/host_firmware/bundle.rs` | A new "NVIDIA Pascal" bundle family, about 0.3 MB on the stick. |
| `stela-loader/src/host_firmware.rs`, `stela-boot-core`, `stela-boot` | The boot's firmware handoff holds 96 images instead of 64. A GTX 1080 needs 20 files, against 3 to 7 for a GSP chip, which with a Realtek network adapter (25 files) and Wi-Fi left too few slots. The `stela` command's own 64-image limit for per-PC manifests is unchanged. |
| `stela-boot/src/engine/gpu/before.rs` | The claim loads the Pascal files and logs that the GPU starts without GSP-RM. |
| Messages and docs | The "supported GPU" messages name the GTX 10 series. |

The 20 files a GTX 1080 uses, as linux-firmware's `WHENCE` links them:

| nouveau asks for | File in linux-firmware |
|---|---|
| `nvidia/gp104/acr/{bl,ucode_load,unload_bl,ucode_unload}.bin` | `nvidia/gp102/acr/…` |
| `nvidia/gp104/gr/{fecs,gpccs}_bl.bin` | `nvidia/gm200/gr/…` |
| `nvidia/gp104/gr/{fecs,gpccs}_{inst,data,sig}.bin` | `nvidia/gp104/gr/…` |
| `nvidia/gp104/gr/sw_{nonctx,ctx,bundle_init,method_init}.bin` | `nvidia/gp102/gr/…` |
| `nvidia/gp104/sec2/{desc,image,sig}-1.bin` | `nvidia/gp102/sec2/…` |
| `nvidia/gp104/nvdec/scrubber.bin` | `nvidia/gp102/nvdec/scrubber.bin` |

SEC2's version 0 files are left out. nouveau asks for them only if version 1
fails, and they would cost three more firmware handoff slots on every boot.

## Build and test

You need what upstream Stela needs: [Rust](https://rustup.rs), git,
Python 3.10 or newer, and LLVM 21, 22 or 23 with Clang, LLD and libclang.

```sh
git clone -b claude/upbeat-sagan-3xwf43 https://github.com/Alwwex/stella_better
cd stella_better
cargo xtask dist
```

This writes `target/release/stela`. The first build fetches and compiles
Linux, Mesa and LLVM and takes a long time.

Make the USB stick with the binary you just built. It downloads the firmware
bundle, Pascal files included:

```sh
sudo ./target/release/stela
```

A stick made with upstream's `stela` lacks the Pascal files. Bring it up to
date with this build:

```sh
sudo ./target/release/stela repair
```

Boot the PC from the stick, then save the log on any computer:

```sh
sudo ./target/release/stela log --output log.txt
```

## Reading the boot log

A good start shows these lines, in this order:

1. The firmware read before the PC's firmware exits, 20 files for the GPU:
   `HOST FIRMWARE BUNDLE USE nvidia/gp102/acr/bl.bin bytes=1280 for pci 10de:1b80`
2. The reset: `GPU 0000:01:00.0: no function-local reset; reset through its
   bridge's secondary bus; …`
3. The firmware handed to nouveau: `GPU gp104: firmware nvidia/gp104/acr/bl.bin
   of 1280 bytes`, then `GPU GP104: Pascal, without GSP-RM: …`
4. nouveau's own lines (prefixed `<6>` and similar), naming the chip `GP104`,
   reading the VBIOS, running devinit, and starting the ACR, SEC2 and GR.
5. `VULKAN DEVICE "…" 10de:1b80 MesaNvk DiscreteGpu vulkan=1.3.… subgroup=32..32`
6. `shaderFloat16 is off: the driver's compiler computes 16-bit float
   arithmetic in 32 bits, rounding each result to 16 bits`

Where it can go wrong, and what that looks like:

| Symptom in the log | Likely cause |
|---|---|
| `HOST FIRMWARE BUNDLE NO RECIPE for the NVIDIA display device at pci 10de:…`, then `the GPU's PMC chipset is unsupported` | The card is not GP102 to GP107. |
| `HOST FIRMWARE BUNDLE LACKS nvidia/…` | The stick was made by upstream `stela`; run `stela repair` with this build. |
| `no function-local reset` followed by a refusal | No Secondary Bus Reset is possible (another device shares the port). Enable VT-d or AMD-Vi so Stela can start the GPU as the firmware left it. |
| nouveau `devinit` errors, such as `VBIOS PMU/DEVINIT not found` or a timeout | Re-POSTing the card after the reset failed. |
| nouveau `acr`, `sec2` or `gr` errors | The signed firmware did not boot. Include the full log in a report. |
| A `VULKAN DEVICE` line, then the Metal device refused for a Vulkan feature it names | A Metal requirement NVK does not meet on Pascal. |

## Known risks

- This path has never run on Pascal hardware inside Stela. nouveau's
  pre-GSP code (devinit, ACR, SEC2, falcon DMA, the classic display engine)
  runs in Stela's Linux environment for the first time.
- NAK's 16-bit to 32-bit lowering on Pascal is deliberate code in Mesa, but
  NVK's conformance runs do not exercise it, because NVK hides
  `shaderFloat16` there.
- Fans stay under the VBIOS's PMU program, as with nouveau on Linux. Watch
  the card's temperature.
