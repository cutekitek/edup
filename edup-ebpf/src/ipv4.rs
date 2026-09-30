//! IPV4-only outer and inner forwarding path.
use aya_ebpf::{macros::xdp, programs::XdpContext};

#[xdp]
pub fn edup_ipv4(ctx: XdpContext) -> u32 {
    crate::handle::<false>(ctx)
}

/// IPV4 INIT handling, tail-called from `edup_ipv4`.
#[xdp]
pub fn edup_handshake_ipv4(ctx: XdpContext) -> u32 {
    crate::handshake_entry::<false>(ctx)
}

/// IPV4 packets authenticated by `edup_open`.
#[xdp]
pub fn edup_accept_ipv4(ctx: XdpContext) -> u32 {
    crate::accept_entry::<false>(ctx)
}
