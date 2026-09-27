//! IPV6-only outer and inner forwarding path.
use aya_ebpf::{macros::xdp, programs::XdpContext};

#[xdp]
pub fn edup_ipv6(ctx: XdpContext) -> u32 {
    crate::handle::<true>(ctx)
}
