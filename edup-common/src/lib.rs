//! Общие для клиента, XDP-программы и загрузчика определения протокола edup.
//!
//! Крейт `no_std` и без зависимостей в базовой конфигурации, чтобы один и тот же
//! код формата пакета и обфускации компилировался и в eBPF, и в userspace.

#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod csum;
pub mod maps;
pub mod wire;

#[cfg(feature = "std")]
pub mod key;
