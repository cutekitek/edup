#[cfg(target_os = "linux")]
#[path = "routes_linux.rs"]
mod platform;
#[cfg(target_os = "windows")]
#[path = "routes_windows.rs"]
mod platform;
pub use platform::{PhysicalRoute, ensure_available};

use anyhow::Result;

pub struct Routes {
    created: Vec<platform::Route>,
}
impl Routes {
    pub fn install(
        physical: &PhysicalRoute,
        interface: &str,
        index: u32,
        server: std::net::IpAddr,
    ) -> Result<Self> {
        let mut guard = Self {
            created: Vec::new(),
        };
        for route in platform::plan(physical, interface, index, server)? {
            route.add()?;
            guard.created.push(route);
        }
        Ok(guard)
    }
    pub fn clear(&mut self) -> Result<()> {
        let mut first = None;
        // Retain failed deletions so Drop can retry; never delete routes we reused.
        for i in (0..self.created.len()).rev() {
            match self.created[i].remove() {
                Ok(()) => {
                    self.created.remove(i);
                }
                Err(error) => {
                    eprintln!("route cleanup failed: {error:#}");
                    if first.is_none() {
                        first = Some(error);
                    }
                }
            }
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
impl Drop for Routes {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}
