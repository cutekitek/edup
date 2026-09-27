//! IPV4-only outer and inner forwarding path.
use aya_ebpf::{macros::xdp, programs::XdpContext};

#[xdp]
pub fn edup_ipv4(ctx: XdpContext) -> u32 {
    crate::handle::<false>(ctx)
}
