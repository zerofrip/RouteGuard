//! Dynamic loading of wireguard.dll and resolution of WireGuardNT exports.

#[cfg(windows)]
mod imp {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use libloading::Library;
    use widestring::U16CStr;

    use super::super::bindings::*;
    use super::super::error::{WgntError, WgntResult};

    macro_rules! resolve_fn {
        ($lib:expr, $name:literal, $ty:ty) => {{
            type FnTy = $ty;
            let sym: libloading::Symbol<FnTy> =
                $lib.get($name.as_bytes())
                    .map_err(|_| WgntError::MissingExport {
                        symbol: $name.into(),
                    })?;
            *sym.into_raw().as_ptr()
        }};
    }

    type CreateAdapterFn = unsafe extern "system" fn(
        *const u16,
        *const u16,
        *const windows_sys::core::GUID,
    ) -> WIREGUARD_ADAPTER_HANDLE;
    type OpenAdapterFn = unsafe extern "system" fn(*const u16) -> WIREGUARD_ADAPTER_HANDLE;
    type CloseAdapterFn = unsafe extern "system" fn(WIREGUARD_ADAPTER_HANDLE);
    type DeleteDriverFn = unsafe extern "system" fn() -> i32;
    type GetAdapterLuidFn = unsafe extern "system" fn(
        WIREGUARD_ADAPTER_HANDLE,
        *mut windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH,
    );
    type GetRunningDriverVersionFn = unsafe extern "system" fn() -> u32;
    type SetConfigurationFn =
        unsafe extern "system" fn(WIREGUARD_ADAPTER_HANDLE, *const WIREGUARD_INTERFACE, u32) -> i32;
    type GetConfigurationFn = unsafe extern "system" fn(
        WIREGUARD_ADAPTER_HANDLE,
        *mut WIREGUARD_INTERFACE,
        *mut u32,
    ) -> i32;
    type SetAdapterStateFn =
        unsafe extern "system" fn(WIREGUARD_ADAPTER_HANDLE, WIREGUARD_ADAPTER_STATE) -> i32;
    type GetAdapterStateFn =
        unsafe extern "system" fn(WIREGUARD_ADAPTER_HANDLE, *mut WIREGUARD_ADAPTER_STATE) -> i32;
    type SetLoggerFn = unsafe extern "system" fn(WIREGUARD_LOGGER_CALLBACK);
    type SetAdapterLoggingFn =
        unsafe extern "system" fn(WIREGUARD_ADAPTER_HANDLE, WIREGUARD_ADAPTER_LOG_STATE) -> i32;

    pub struct WgntLibrary {
        _library: Library,
        pub path: PathBuf,
        create_adapter: CreateAdapterFn,
        open_adapter: OpenAdapterFn,
        close_adapter: CloseAdapterFn,
        delete_driver: DeleteDriverFn,
        get_adapter_luid: GetAdapterLuidFn,
        get_running_driver_version: GetRunningDriverVersionFn,
        set_configuration: SetConfigurationFn,
        get_configuration: GetConfigurationFn,
        set_adapter_state: SetAdapterStateFn,
        get_adapter_state: GetAdapterStateFn,
        #[allow(dead_code)]
        set_logger: SetLoggerFn,
        #[allow(dead_code)]
        set_adapter_logging: SetAdapterLoggingFn,
    }

    impl WgntLibrary {
        pub fn load(path: impl AsRef<Path>) -> WgntResult<Arc<Self>> {
            let path = path.as_ref().to_path_buf();
            if !path.exists() {
                return Err(WgntError::DllNotFound {
                    path: path.display().to_string(),
                });
            }

            let library = unsafe { Library::new(&path) }
                .map_err(|e| WgntError::DllLoad(format!("{}: {e}", path.display())))?;

            unsafe {
                Ok(Arc::new(Self {
                    path: path.clone(),
                    create_adapter: resolve_fn!(library, "WireGuardCreateAdapter", CreateAdapterFn),
                    open_adapter: resolve_fn!(library, "WireGuardOpenAdapter", OpenAdapterFn),
                    close_adapter: resolve_fn!(library, "WireGuardCloseAdapter", CloseAdapterFn),
                    delete_driver: resolve_fn!(library, "WireGuardDeleteDriver", DeleteDriverFn),
                    get_adapter_luid: resolve_fn!(
                        library,
                        "WireGuardGetAdapterLUID",
                        GetAdapterLuidFn
                    ),
                    get_running_driver_version: resolve_fn!(
                        library,
                        "WireGuardGetRunningDriverVersion",
                        GetRunningDriverVersionFn
                    ),
                    set_configuration: resolve_fn!(
                        library,
                        "WireGuardSetConfiguration",
                        SetConfigurationFn
                    ),
                    get_configuration: resolve_fn!(
                        library,
                        "WireGuardGetConfiguration",
                        GetConfigurationFn
                    ),
                    set_adapter_state: resolve_fn!(
                        library,
                        "WireGuardSetAdapterState",
                        SetAdapterStateFn
                    ),
                    get_adapter_state: resolve_fn!(
                        library,
                        "WireGuardGetAdapterState",
                        GetAdapterStateFn
                    ),
                    set_logger: resolve_fn!(library, "WireGuardSetLogger", SetLoggerFn),
                    set_adapter_logging: resolve_fn!(
                        library,
                        "WireGuardSetAdapterLogging",
                        SetAdapterLoggingFn
                    ),
                    _library: library,
                }))
            }
        }

        pub fn driver_version(&self) -> WgntResult<u32> {
            let v = unsafe { (self.get_running_driver_version)() };
            if v == 0 {
                Err(WgntError::last_error("WireGuardGetRunningDriverVersion"))
            } else {
                Ok(v)
            }
        }

        pub fn delete_driver(&self) -> WgntResult<()> {
            let ok = unsafe { (self.delete_driver)() };
            if ok == 0 {
                Err(WgntError::last_error("WireGuardDeleteDriver"))
            } else {
                Ok(())
            }
        }

        pub fn create_adapter(
            &self,
            name: &str,
            tunnel_type: &str,
        ) -> WgntResult<WIREGUARD_ADAPTER_HANDLE> {
            let name = U16CStr::from_str(name).map_err(|e| WgntError::Config(e.to_string()))?;
            let tunnel_type =
                U16CStr::from_str(tunnel_type).map_err(|e| WgntError::Config(e.to_string()))?;
            let handle = unsafe {
                (self.create_adapter)(name.as_ptr(), tunnel_type.as_ptr(), std::ptr::null())
            };
            if handle.is_null() {
                Err(WgntError::last_error("WireGuardCreateAdapter"))
            } else {
                Ok(handle)
            }
        }

        pub fn open_adapter(&self, name: &str) -> WgntResult<WIREGUARD_ADAPTER_HANDLE> {
            let name = U16CStr::from_str(name).map_err(|e| WgntError::Config(e.to_string()))?;
            let handle = unsafe { (self.open_adapter)(name.as_ptr()) };
            if handle.is_null() {
                Err(WgntError::last_error("WireGuardOpenAdapter"))
            } else {
                Ok(handle)
            }
        }

        pub fn close_adapter(&self, handle: WIREGUARD_ADAPTER_HANDLE) {
            if !handle.is_null() {
                unsafe { (self.close_adapter)(handle) };
            }
        }

        pub fn get_adapter_luid(&self, handle: WIREGUARD_ADAPTER_HANDLE) -> WgntResult<u64> {
            let mut luid = windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH { Value: 0 };
            unsafe { (self.get_adapter_luid)(handle, &mut luid) };
            Ok(luid.Value)
        }

        pub fn set_configuration(
            &self,
            handle: WIREGUARD_ADAPTER_HANDLE,
            config: &[u8],
        ) -> WgntResult<()> {
            let ok = unsafe {
                (self.set_configuration)(
                    handle,
                    config.as_ptr() as *const WIREGUARD_INTERFACE,
                    config.len() as u32,
                )
            };
            if ok == 0 {
                Err(WgntError::last_error("WireGuardSetConfiguration"))
            } else {
                Ok(())
            }
        }

        pub fn get_configuration(
            &self,
            handle: WIREGUARD_ADAPTER_HANDLE,
            buf: &mut [u8],
        ) -> WgntResult<usize> {
            let mut bytes = buf.len() as u32;
            let ok = unsafe {
                (self.get_configuration)(
                    handle,
                    buf.as_mut_ptr() as *mut WIREGUARD_INTERFACE,
                    &mut bytes,
                )
            };
            if ok == 0 {
                let err = WgntError::last_error("WireGuardGetConfiguration");
                if let WgntError::Api { code, .. } = err {
                    if code == windows_sys::Win32::Foundation::ERROR_MORE_DATA {
                        return Ok(bytes as usize);
                    }
                }
                Err(err)
            } else {
                Ok(bytes as usize)
            }
        }

        pub fn set_adapter_state(
            &self,
            handle: WIREGUARD_ADAPTER_HANDLE,
            state: WIREGUARD_ADAPTER_STATE,
        ) -> WgntResult<()> {
            let ok = unsafe { (self.set_adapter_state)(handle, state) };
            if ok == 0 {
                Err(WgntError::last_error("WireGuardSetAdapterState"))
            } else {
                Ok(())
            }
        }

        pub fn get_adapter_state(
            &self,
            handle: WIREGUARD_ADAPTER_HANDLE,
        ) -> WgntResult<WIREGUARD_ADAPTER_STATE> {
            let mut state = WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_DOWN;
            let ok = unsafe { (self.get_adapter_state)(handle, &mut state) };
            if ok == 0 {
                Err(WgntError::last_error("WireGuardGetAdapterState"))
            } else {
                Ok(state)
            }
        }
    }

    unsafe impl Send for WgntLibrary {}
    unsafe impl Sync for WgntLibrary {}
}

#[cfg(windows)]
pub use imp::WgntLibrary;

#[cfg(not(windows))]
pub struct WgntLibrary;

#[cfg(not(windows))]
impl WgntLibrary {
    pub fn load(
        _path: impl AsRef<std::path::Path>,
    ) -> super::error::WgntResult<std::sync::Arc<Self>> {
        Err(super::error::WgntError::UnsupportedPlatform)
    }
}
