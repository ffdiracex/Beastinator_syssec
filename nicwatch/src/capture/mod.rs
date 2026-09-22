//!  Cross-platform packet capture
//! with ui

use crate::domain::{Frame, LinkType};
use crate::error::Result;

#[cfg(target_os = "freebsd")]
pub mod backend_freebsd;
#[cfg(target_os = "linux")]
pub mod backend_linux;


pub mod source;
pub mod stats;

#[cfg(target_os = "freebsd")]
pub use backend_freebsd::{BpfConfig, BpfCapture};
#[cfg(target_os = "linux")]
pub use backend_linux::{AfPacketConfig, AfPacketCapture};


pub use source::{FrameSource, FrameRx, FrameTx, LiveSource, SyntheticSource, Scenario};
pub use stats::{if_stats, list_interfaces, MacContext};

pub trait CaptureBackend: Send {
	fn name(&self) -> &str;
	fn link_type(&self) -> LinkType;
	fn interface(&self) -> &str;

	fn read_batch(&mut self, sink: &mut dyn FnMut(Frame)) -> Result<usize>;
}

pub type BoxedBackend = Box<dyn CaptureBackend>;

// build platform-default interface
pub fn open_default(interface: &str, promisc: bool) -> Result<BoxedBackend> {
	#[cfg(target_os = "freebsd")]
	{
		let cfg = BpfConfig::new(interface).promiscuous(promisc);
		Ok(Box::new(BpfCapture::open(cfg)?))
	}
	#[cfg(target_os = "linux")]
	{
		let cfg = AfPacketConfig::new(interface).promiscuous(promisc);
		Ok(Box::new(AfPacketCapture::open(cfg)?))
	}
	#[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
	{
		let _ = (interface, promisc);
		Err(crate::error::Error::Config("unsupported platform, nicwatch supports freebsd and linux".into(),
		))
	}
}

		
