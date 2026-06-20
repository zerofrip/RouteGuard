//! Safe adapter handle wrapping WireGuardNT adapter lifecycle.

#[cfg(windows)]
mod imp {
    use std::sync::Arc;

    use super::super::bindings::{WIREGUARD_ADAPTER_HANDLE, WIREGUARD_ADAPTER_STATE};
    use super::super::error::{WgntError, WgntResult};
    use super::super::ffi::WgntLibrary;

    pub const DEFAULT_POOL: &str = "RouteGuard";

    pub struct AdapterHandle {
        pub(crate) library: Arc<WgntLibrary>,
        handle: WIREGUARD_ADAPTER_HANDLE,
        pub created: bool,
        closed: bool,
    }

    impl AdapterHandle {
        pub fn open_or_create(library: Arc<WgntLibrary>, name: &str) -> WgntResult<(Self, bool)> {
            match library.open_adapter(name) {
                Ok(handle) => Ok((
                    Self {
                        library,
                        handle,
                        created: false,
                        closed: false,
                    },
                    false,
                )),
                Err(WgntError::Api { code, .. }) if code == 2 => {
                    // ERROR_FILE_NOT_FOUND
                    let handle = library.create_adapter(name, DEFAULT_POOL)?;
                    Ok((
                        Self {
                            library,
                            handle,
                            created: true,
                            closed: false,
                        },
                        true,
                    ))
                }
                Err(e) => Err(e),
            }
        }

        pub fn raw(&self) -> WIREGUARD_ADAPTER_HANDLE {
            self.handle
        }

        pub fn luid(&self) -> WgntResult<u64> {
            self.library.get_adapter_luid(self.handle)
        }

        pub fn set_configuration(&self, config: &[u8]) -> WgntResult<()> {
            self.library.set_configuration(self.handle, config)
        }

        pub fn set_adapter_state(&self, state: WIREGUARD_ADAPTER_STATE) -> WgntResult<()> {
            self.library.set_adapter_state(self.handle, state)
        }

        pub fn get_adapter_state(&self) -> WgntResult<WIREGUARD_ADAPTER_STATE> {
            self.library.get_adapter_state(self.handle)
        }

        pub fn close(&mut self) {
            if !self.closed {
                self.library.close_adapter(self.handle);
                self.closed = true;
            }
        }
    }

    impl Drop for AdapterHandle {
        fn drop(&mut self) {
            self.close();
        }
    }

    unsafe impl Send for AdapterHandle {}
    unsafe impl Sync for AdapterHandle {}
}

#[cfg(windows)]
pub use imp::{AdapterHandle, DEFAULT_POOL};
