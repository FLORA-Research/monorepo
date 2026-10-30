# CYW43439 radio firmware, required by the aggregator binary.
#
# These are vendored rather than fetched at build time. A build that reaches the
# network is a build that fails when the network does, and a firmware image that
# changes without a commit is a firmware image nobody can reproduce. The blobs
# are the ones embassy ships for the RP2040's radio; `43439A0.bin` is the chip's
# own firmware, `43439A0_clm.bin` its regulatory table, and `nvram_rp2040.bin`
# the board's calibration data.
#
# They are loaded by `cyw43::aligned_bytes!` in `src/main.rs`.
