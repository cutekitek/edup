//! IPV6-only outer and inner forwarding path.
use aya_ebpf::{macros::xdp, programs::XdpContext};

#[xdp]
pub fn edup_ipv6(ctx: XdpContext) -> u32 {
    crate::handle::<true>(ctx)
}

/// IPV6 INIT handling, tail-called from `edup_ipv6`.
#[xdp]
pub fn edup_handshake_ipv6(ctx: XdpContext) -> u32 {
    crate::handshake_entry::<true>(ctx)
}

/// IPV6 packets authenticated by `edup_open`.
#[xdp]
pub fn edup_accept_ipv6(ctx: XdpContext) -> u32 {
    crate::accept_entry::<true>(ctx)
}
