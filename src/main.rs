#![windows_subsystem = "windows"]

mod fido_manager;
mod models;
mod windows_hello;

slint::include_modules!();

use fido_manager::FidoKeyManager;
use models::DeviceDescriptor;
use slint::{ModelRc, SharedString, VecModel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use windows_hello::WindowsHelloManager;
use windows::Win32::Graphics::Dwm::DwmGetColorizationColor;

struct AppState {
    devices: Vec<DeviceDescriptor>,
    current_device_id: Option<String>,
    current_pin: String,
}

fn get_windows_accent_color() -> slint::Color {
    let mut color: u32 = 0;
    let mut opaque: windows::Win32::Foundation::BOOL = windows::Win32::Foundation::BOOL(0);
    unsafe {
        if DwmGetColorizationColor(&mut color, &mut opaque).is_ok() {
            let r = ((color >> 16) & 0xFF) as u8;
            let g = ((color >> 8) & 0xFF) as u8;
            let b = (color & 0xFF) as u8;
            return slint::Color::from_rgb_u8(r, g, b);
        }
    }
    slint::Color::from_rgb_u8(97, 175, 239) 
}

fn main() -> Result<(), slint::PlatformError> {
    let main_window = MainWindow::new()?;
    main_window.set_accent_color(get_windows_accent_color());

    let state = Arc::new(Mutex::new(AppState {
        devices: Vec::new(),
        current_device_id: None,
        current_pin: String::new(),
    }));

    let hello_manager = Arc::new(WindowsHelloManager::new());

    // ==========================================
    // 1. Thread Auto-Detect
    // ==========================================
    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);

        thread::spawn(move || {
            let fido = FidoKeyManager::new();
            let mut last_detected_ids: Vec<String> = Vec::new();

            loop {
                if let Ok(devices) = fido.enumerate_devices() {
                    let current_ids: Vec<String> = devices.iter().map(|d| d.raw_id.clone()).collect();
                    
                    if current_ids != last_detected_ids {
                        last_detected_ids = current_ids.clone();
                        let devs_clone = devices.clone();
                        let state_arc = Arc::clone(&state_clone);

                        let _ = slint::invoke_from_event_loop({
                            let window_weak = window_weak.clone();
                            move || {
                                if let Some(ui) = window_weak.upgrade() {
                                    let mut s = state_arc.lock().unwrap();
                                    s.devices = devs_clone.clone();

                                    let display_names: Vec<SharedString> = devs_clone
                                        .iter()
                                        .map(|d| SharedString::from(d.display_name.as_str()))
                                        .collect();
                                    ui.set_device_list(ModelRc::new(VecModel::from(display_names)));

                                    let mut device_still_present = false;
                                    if let Some(ref active_id) = s.current_device_id {
                                        if devs_clone.iter().any(|d| &d.raw_id == active_id) {
                                            device_still_present = true;
                                        }
                                    }

                                    if !device_still_present {
                                        s.current_device_id = None;
                                        s.current_pin = String::new();
                                        
                                        ui.set_selected_device_index(if devs_clone.is_empty() { -1 } else { 0 });
                                        ui.set_device_ready(false);
                                        ui.set_extra_approval_granted(false);
                                        ui.set_info_list(ModelRc::new(VecModel::from(Vec::<InfoEntry>::new())));
                                        ui.set_settings_list(ModelRc::new(VecModel::from(Vec::<InfoEntry>::new())));
                                        ui.set_passkeys(ModelRc::new(VecModel::from(Vec::<PasskeyEntry>::new())));
                                        ui.set_fingerprints(ModelRc::new(VecModel::from(Vec::<FingerprintEntry>::new())));
                                        
                                        ui.set_show_pin_modal(false);
                                        ui.set_show_change_pin_modal(false);
                                        ui.set_show_delete_modal(false);
                                        ui.set_show_about_modal(false);
                                        
                                        if devs_clone.is_empty() {
                                            ui.set_status_message(SharedString::from("Waiting for USB key connection..."));
                                        } else {
                                            ui.set_status_message(SharedString::from("Key detected. PIN authentication is required."));
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
                thread::sleep(Duration::from_millis(1000));
            }
        });
    }

    // ==========================================
    // 2. PIN Access Modal
    // ==========================================
    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);

        main_window.on_request_device_access(move |index| {
            if index < 0 { return; }

            let dev_id = {
                let s = state_clone.lock().unwrap();
                s.devices[index as usize].raw_id.clone()
            };

            let window_clone = window_weak.clone();
            
            if let Some(ui) = window_clone.upgrade() {
                ui.set_pending_device_index(index);
                ui.set_pin_input_text(SharedString::from(""));
                ui.set_pin_error_message(SharedString::from(""));
                ui.set_pin_retries_left(-1);
                ui.set_show_pin_modal(true);
            }

            thread::spawn(move || {
                let fido = FidoKeyManager::new();
                let retries = fido.get_pin_retries(&dev_id).unwrap_or(-1);
                
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = window_clone.upgrade() {
                        ui.set_pin_retries_left(retries);
                    }
                });
            });
        });
    }

    {
        let window_weak = main_window.as_weak();
        main_window.on_cancel_pin(move || {
            if let Some(ui) = window_weak.upgrade() {
                ui.set_show_pin_modal(false);
            }
        });
    }

    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);

        main_window.on_submit_pin(move |index, pin_input| {
            if index < 0 { return; }

            let window_clone = window_weak.clone();
            let state_arc = Arc::clone(&state_clone);
            
            let device_id = {
                let s = state_arc.lock().unwrap();
                s.devices[index as usize].raw_id.clone()
            };
            let pin = pin_input.to_string();

            if let Some(ui) = window_clone.upgrade() {
                ui.set_pin_error_message(SharedString::from("Unlocking and synchronizing data..."));
            }

            thread::spawn(move || {
                let fido = FidoKeyManager::new();
                
                let caps_res = fido.inspect_device(&device_id, &pin);
                let passkeys_res = if caps_res.is_ok() { fido.list_passkeys(&device_id, &pin) } else { Err(anyhow::anyhow!("Bypassed")) };
                let fingerprints_res = if caps_res.is_ok() { fido.list_fingerprints(&device_id, &pin) } else { Err(anyhow::anyhow!("Bypassed")) };

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = window_clone.upgrade() {
                        match caps_res {
                            Ok(caps) => {
                                {
                                    let mut s = state_arc.lock().unwrap();
                                    s.current_device_id = Some(device_id.clone());
                                    s.current_pin = pin.clone();
                                }

                                ui.set_show_pin_modal(false);
                                
                                let info_models: Vec<InfoEntry> = caps.raw_info.into_iter()
                                    .map(|(k, v)| InfoEntry { key: SharedString::from(k), value: SharedString::from(v) })
                                    .collect();
                                ui.set_info_list(ModelRc::new(VecModel::from(info_models)));

                                let settings_models: Vec<InfoEntry> = caps.settings_info.into_iter()
                                    .map(|(k, v)| InfoEntry { key: SharedString::from(k), value: SharedString::from(v) })
                                    .collect();
                                ui.set_settings_list(ModelRc::new(VecModel::from(settings_models)));

                                ui.set_has_bio(caps.supports_bio_enroll);
                                ui.set_has_uv(caps.supports_fido2_1);
                                ui.set_device_ready(true);
                                ui.set_extra_approval_granted(false);
                                ui.set_status_message(SharedString::from("Device unlocked and read successfully."));

                                if let Ok(keys) = passkeys_res {
                                    let pk_entries: Vec<PasskeyEntry> = keys.into_iter()
                                        .map(|k| PasskeyEntry {
                                            credential_id: SharedString::from(k.credential_id),
                                            user: SharedString::from(k.user),
                                            user_id: SharedString::from(k.user_id),
                                            display_name: SharedString::from(k.display_name),
                                            domain: SharedString::from(k.domain),
                                            protection: SharedString::from(k.protection),
                                        }).collect();
                                    ui.set_passkeys(ModelRc::new(VecModel::from(pk_entries)));
                                }

                                if let Ok(fps) = fingerprints_res {
                                    let fp_entries: Vec<FingerprintEntry> = fps.into_iter()
                                        .map(|f| FingerprintEntry {
                                            index: SharedString::from(f.index),
                                            description: SharedString::from(f.description),
                                        }).collect();
                                    ui.set_fingerprints(ModelRc::new(VecModel::from(fp_entries)));
                                }
                            }
                            Err(_) => {
                                let retries = fido.get_pin_retries(&device_id).unwrap_or(-1);
                                ui.set_pin_retries_left(retries);
                                
                                if retries == 0 {
                                    ui.set_pin_error_message(SharedString::from("Incorrect PIN! Device is blocked."));
                                } else {
                                    ui.set_pin_error_message(SharedString::from("Incorrect PIN! Please try again."));
                                }
                            }
                        }
                    }
                });
            });
        });
    }

    // ==========================================
    // 3. Change PIN Flow
    // ==========================================
    {
        let window_weak = main_window.as_weak();
        main_window.on_request_change_pin(move || {
            if let Some(ui) = window_weak.upgrade() {
                ui.set_new_pin_input(SharedString::from(""));
                ui.set_confirm_new_pin_input(SharedString::from(""));
                ui.set_change_pin_error_message(SharedString::from(""));
                ui.set_show_change_pin_modal(true);
            }
        });
    }

    {
        let window_weak = main_window.as_weak();
        main_window.on_cancel_change_pin(move || {
            if let Some(ui) = window_weak.upgrade() {
                ui.set_show_change_pin_modal(false);
            }
        });
    }

    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);

        main_window.on_submit_change_pin(move |new_pin_val, confirm_pin_val| {
            let window_clone = window_weak.clone();

            if new_pin_val != confirm_pin_val {
                if let Some(ui) = window_clone.upgrade() {
                    ui.set_change_pin_error_message(SharedString::from("PINs do not match!"));
                }
                return;
            }

            let (dev_id, old_pin) = {
                let s = state_clone.lock().unwrap();
                (s.current_device_id.clone(), s.current_pin.clone())
            };
            
            if let Some(dev_id) = dev_id {
                if let Some(ui) = window_clone.upgrade() {
                    ui.set_change_pin_error_message(SharedString::from("Processing write..."));
                }

                let new_pin_str = new_pin_val.to_string();
                let state_arc = Arc::clone(&state_clone);

                thread::spawn(move || {
                    let fido = FidoKeyManager::new();
                    let result = fido.change_pin(&dev_id, &old_pin, &new_pin_str);
                    
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = window_clone.upgrade() {
                            match result {
                                Ok(_) => {
                                    if let Ok(mut s) = state_arc.lock() {
                                        s.current_pin = new_pin_str;
                                    }
                                    ui.set_show_change_pin_modal(false);
                                    ui.set_status_message(SharedString::from("PIN successfully changed and secured."));
                                }
                                Err(e) => ui.set_change_pin_error_message(SharedString::from(format!("Error: {}", e))),
                            }
                        }
                    });
                });
            }
        });
    }

    // ==========================================
    // 4. CTAP Operations & Delete Flow
    // ==========================================
    {
        let window_weak = main_window.as_weak();
        main_window.on_open_website(move |domain| {
            let url = format!("https://{}", domain);
            let _ = std::process::Command::new("cmd").args(&["/C", "start", &url]).spawn();
            if let Some(ui) = window_weak.upgrade() {
                ui.set_show_delete_modal(false);
            }
        });
    }

    main_window.on_open_windows_passkey_settings(move || {
        let _ = std::process::Command::new("cmd").args(&["/C", "start", "ms-settings:passkeys"]).spawn();
    });

    main_window.on_open_github_repo(move || {
        let _ = std::process::Command::new("cmd").args(&["/C", "start", "https://github.com/ionuttbara/fido2manager"]).spawn();
    });

    {
        let window_weak = main_window.as_weak();
        let hello_arc = Arc::clone(&hello_manager);
        let state_clone = Arc::clone(&state);

        main_window.on_unlock_via_windows_hello(move || {
            let window_clone = window_weak.clone();
            let hello = Arc::clone(&hello_arc);
            let dev_id = {
                let s = state_clone.lock().unwrap();
                s.current_device_id.clone()
            };

            thread::spawn(move || {
                let result = hello.verify_user_presence("FIDO2 Passkey Administrator Authorization");
                
                if let Ok(true) = result {
                    let _ = slint::invoke_from_event_loop({
                        let window_clone = window_clone.clone();
                        move || {
                            if let Some(ui) = window_clone.upgrade() {
                                ui.set_status_message(SharedString::from("Windows Hello approved. Now touch the physical FIDO key..."));
                            }
                        }
                    });

                    if let Some(dev_id) = dev_id {
                        let fido = FidoKeyManager::new();
                        let touch_res = fido.wait_for_touch(&dev_id);
                        
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = window_clone.upgrade() {
                                match touch_res {
                                    Ok(_) => {
                                        ui.set_extra_approval_granted(true);
                                        ui.set_status_message(SharedString::from("Extra approval granted (Windows Hello + Physical Touch)."));
                                    }
                                    Err(e) => {
                                        ui.set_status_message(SharedString::from(format!("Physical Touch failed: {}", e)));
                                    }
                                }
                            }
                        });
                    }
                } else {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = window_clone.upgrade() {
                            ui.set_status_message(SharedString::from("Windows Hello: Cancelled or Failed."));
                        }
                    });
                }
            });
        });
    }

    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);

        main_window.on_confirm_delete_passkey(move |credential_id| {
            let (dev_id, pin) = {
                let s = state_clone.lock().unwrap();
                (s.current_device_id.clone(), s.current_pin.clone())
            };
            if let Some(dev_id) = dev_id {
                let window_clone = window_weak.clone();
                let cred_id_str = credential_id.to_string();

                if let Some(ui) = window_clone.upgrade() {
                    ui.set_show_delete_modal(false);
                    ui.set_status_message(SharedString::from("Deleting Passkey..."));
                }

                thread::spawn(move || {
                    let fido = FidoKeyManager::new();
                    let result = fido.delete_passkey(&dev_id, &pin, &cred_id_str);
                    let refreshed = if result.is_ok() { fido.list_passkeys(&dev_id, &pin).ok() } else { None };
                    
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = window_clone.upgrade() {
                            match result {
                                Ok(_) => {
                                    if let Some(keys) = refreshed {
                                        let entries: Vec<PasskeyEntry> = keys.into_iter().map(|k| PasskeyEntry {
                                            credential_id: SharedString::from(k.credential_id),
                                            user: SharedString::from(k.user),
                                            user_id: SharedString::from(k.user_id),
                                            display_name: SharedString::from(k.display_name),
                                            domain: SharedString::from(k.domain),
                                            protection: SharedString::from(k.protection),
                                        }).collect();
                                        ui.set_passkeys(ModelRc::new(VecModel::from(entries)));
                                        ui.set_selected_passkey_index(-1);
                                    }
                                    ui.set_status_message(SharedString::from("Passkey deleted and list refreshed."));
                                }
                                Err(e) => ui.set_status_message(SharedString::from(format!("Error: {}", e))),
                            }
                        }
                    });
                });
            }
        });
    }

    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);

        main_window.on_add_fingerprint(move || {
            let (dev_id, pin) = {
                let s = state_clone.lock().unwrap();
                (s.current_device_id.clone(), s.current_pin.clone())
            };
            if let Some(dev_id) = dev_id {
                let window_clone = window_weak.clone();
                if let Some(ui) = window_clone.upgrade() {
                    ui.set_status_message(SharedString::from("Touch the sensor repeatedly to complete the scan..."));
                }
                thread::spawn(move || {
                    let fido = FidoKeyManager::new();
                    let result = fido.add_fingerprint(&dev_id, &pin);
                    let refreshed = if result.is_ok() { fido.list_fingerprints(&dev_id, &pin).ok() } else { None };
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = window_clone.upgrade() {
                            match result {
                                Ok(_) => {
                                    if let Some(fps) = refreshed {
                                        let entries: Vec<FingerprintEntry> = fps.into_iter().map(|f| FingerprintEntry {
                                            index: SharedString::from(f.index),
                                            description: SharedString::from(f.description),
                                        }).collect();
                                        ui.set_fingerprints(ModelRc::new(VecModel::from(entries)));
                                    }
                                    ui.set_status_message(SharedString::from("Biometric template saved and list refreshed."));
                                }
                                Err(e) => ui.set_status_message(SharedString::from(format!("Biometric error: {}", e))),
                            }
                        }
                    });
                });
            }
        });
    }

    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);

        main_window.on_delete_fingerprint(move |template_id| {
            let (dev_id, pin) = {
                let s = state_clone.lock().unwrap();
                (s.current_device_id.clone(), s.current_pin.clone())
            };
            if let Some(dev_id) = dev_id {
                let window_clone = window_weak.clone();
                let template_id_str = template_id.to_string();
                if let Some(ui) = window_clone.upgrade() {
                    ui.set_status_message(SharedString::from("Touch the sensor to delete the fingerprint..."));
                }
                thread::spawn(move || {
                    let fido = FidoKeyManager::new();
                    let result = fido.delete_fingerprint(&dev_id, &pin, &template_id_str);
                    let refreshed = if result.is_ok() { fido.list_fingerprints(&dev_id, &pin).ok() } else { None };
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = window_clone.upgrade() {
                            match result {
                                Ok(_) => {
                                    if let Some(fps) = refreshed {
                                        let entries: Vec<FingerprintEntry> = fps.into_iter().map(|f| FingerprintEntry {
                                            index: SharedString::from(f.index),
                                            description: SharedString::from(f.description),
                                        }).collect();
                                        ui.set_fingerprints(ModelRc::new(VecModel::from(entries)));
                                        ui.set_selected_fingerprint_index(-1);
                                    }
                                    ui.set_status_message(SharedString::from("Fingerprint removed and list refreshed."));
                                }
                                Err(e) => ui.set_status_message(SharedString::from(format!("Deletion error: {}", e))),
                            }
                        }
                    });
                });
            }
        });
    }

    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);

        main_window.on_enforce_uv(move || {
            let (dev_id, pin) = {
                let s = state_clone.lock().unwrap();
                (s.current_device_id.clone(), s.current_pin.clone())
            };
            if let Some(dev_id) = dev_id {
                let window_clone = window_weak.clone();
                thread::spawn(move || {
                    let fido = FidoKeyManager::new();
                    let result = fido.enforce_uv(&dev_id, &pin);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = window_clone.upgrade() {
                            match result {
                                Ok(_) => ui.set_status_message(SharedString::from("The platform will now require biometrics by default (Always-UV).")),
                                Err(e) => ui.set_status_message(SharedString::from(format!("Security error: {}", e))),
                            }
                        }
                    });
                });
            }
        });
    }

    // ==========================================
    // 5. Fast refresh / session / extra FIDO tools
    // ==========================================
    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);
        main_window.on_refresh_devices(move || {
            let window_clone = window_weak.clone();
            let state_arc = Arc::clone(&state_clone);
            thread::spawn(move || {
                let fido = FidoKeyManager::new();
                let devices = fido.enumerate_devices().unwrap_or_default();
                let names: Vec<SharedString> = devices.iter().map(|d| SharedString::from(d.display_name.as_str())).collect();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = window_clone.upgrade() {
                        if let Ok(mut s) = state_arc.lock() { s.devices = devices.clone(); }
                        ui.set_device_list(ModelRc::new(VecModel::from(names)));
                        if ui.get_selected_device_index() < 0 && !devices.is_empty() { ui.set_selected_device_index(0); }
                        ui.set_status_message(SharedString::from(if devices.is_empty() { "No FIDO key detected." } else { "Device scan completed." }));
                    }
                });
            });
        });
    }

    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);
        main_window.on_refresh_data(move || {
            let (dev_id, pin) = {
                let s = state_clone.lock().unwrap();
                (s.current_device_id.clone(), s.current_pin.clone())
            };
            let Some(dev_id) = dev_id else { return; };
            let window_clone = window_weak.clone();
            thread::spawn(move || {
                let fido = FidoKeyManager::new();
                let caps = fido.inspect_device(&dev_id, &pin);
                let passkeys = fido.list_passkeys(&dev_id, &pin);
                let fingerprints = fido.list_fingerprints(&dev_id, &pin);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = window_clone.upgrade() {
                        if let Ok(c) = caps {
                            ui.set_info_list(ModelRc::new(VecModel::from(c.raw_info.into_iter().map(|(k,v)| InfoEntry { key: k.into(), value: v.into() }).collect::<Vec<_>>() )));
                            ui.set_settings_list(ModelRc::new(VecModel::from(c.settings_info.into_iter().map(|(k,v)| InfoEntry { key: k.into(), value: v.into() }).collect::<Vec<_>>() )));
                            ui.set_has_bio(c.supports_bio_enroll);
                            ui.set_has_uv(c.supports_fido2_1);
                        }
                        if let Ok(keys) = passkeys {
                            ui.set_passkeys(ModelRc::new(VecModel::from(keys.into_iter().map(|k| PasskeyEntry { credential_id:k.credential_id.into(), user:k.user.into(), user_id:k.user_id.into(), display_name:k.display_name.into(), domain:k.domain.into(), protection:k.protection.into() }).collect::<Vec<_>>() )));
                            ui.set_selected_passkey_index(-1);
                        }
                        if let Ok(fps) = fingerprints {
                            ui.set_fingerprints(ModelRc::new(VecModel::from(fps.into_iter().map(|f| FingerprintEntry { index:f.index.into(), description:f.description.into() }).collect::<Vec<_>>() )));
                            ui.set_selected_fingerprint_index(-1);
                        }
                        ui.set_status_message(SharedString::from("Authenticator data refreshed."));
                    }
                });
            });
        });
    }

    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);
        main_window.on_lock_session(move || {
            if let Ok(mut s) = state_clone.lock() {
                s.current_device_id = None;
                s.current_pin.clear();
            }
            if let Some(ui) = window_weak.upgrade() {
                ui.set_device_ready(false);
                ui.set_extra_approval_granted(false);
                ui.set_passkeys(ModelRc::new(VecModel::from(Vec::<PasskeyEntry>::new())));
                ui.set_fingerprints(ModelRc::new(VecModel::from(Vec::<FingerprintEntry>::new())));
                ui.set_settings_list(ModelRc::new(VecModel::from(Vec::<InfoEntry>::new())));
                ui.set_status_message(SharedString::from("Session locked. PIN cleared from memory."));
                ui.set_active_tab(0);
            }
        });
    }

    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);
        main_window.on_test_touch(move || {
            let dev_id = state_clone.lock().ok().and_then(|s| s.current_device_id.clone());
            let Some(dev_id) = dev_id else { return; };
            let window_clone = window_weak.clone();
            if let Some(ui) = window_clone.upgrade() { ui.set_status_message("Touch the security key now...".into()); }
            thread::spawn(move || {
                let result = FidoKeyManager::new().wait_for_touch(&dev_id);
                let _ = slint::invoke_from_event_loop(move || if let Some(ui) = window_clone.upgrade() {
                    ui.set_status_message(match result { Ok(_) => "Physical presence confirmed.".into(), Err(e) => format!("Touch test failed: {}", e).into() });
                });
            });
        });
    }

    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);
        main_window.on_wink_key(move || {
            let dev_id = state_clone.lock().ok().and_then(|s| s.current_device_id.clone());
            let Some(dev_id) = dev_id else { return; };
            let window_clone = window_weak.clone();
            thread::spawn(move || {
                let result = FidoKeyManager::new().wink(&dev_id);
                let _ = slint::invoke_from_event_loop(move || if let Some(ui) = window_clone.upgrade() {
                    ui.set_status_message(match result { Ok(_) => "Key identification signal sent.".into(), Err(e) => format!("Wink unsupported/failed: {}", e).into() });
                });
            });
        });
    }

    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);
        main_window.on_rename_fingerprint(move |template_id, name| {
            let (dev_id, pin) = { let s = state_clone.lock().unwrap(); (s.current_device_id.clone(), s.current_pin.clone()) };
            let Some(dev_id) = dev_id else { return; };
            let template_id = template_id.to_string();
            let name = name.to_string();
            let window_clone = window_weak.clone();
            thread::spawn(move || {
                let fido = FidoKeyManager::new();
                let result = fido.rename_fingerprint(&dev_id, &pin, &template_id, &name);
                let refreshed = if result.is_ok() { fido.list_fingerprints(&dev_id, &pin).ok() } else { None };
                let _ = slint::invoke_from_event_loop(move || if let Some(ui) = window_clone.upgrade() {
                    if let Some(fps) = refreshed {
                        ui.set_fingerprints(ModelRc::new(VecModel::from(fps.into_iter().map(|f| FingerprintEntry { index:f.index.into(), description:f.description.into() }).collect::<Vec<_>>() )));
                    }
                    ui.set_show_rename_fingerprint_modal(false);
                    ui.set_status_message(match result { Ok(_) => "Fingerprint renamed.".into(), Err(e) => format!("Rename failed: {}", e).into() });
                });
            });
        });
    }

    {
        let window_weak = main_window.as_weak();
        let state_clone = Arc::clone(&state);

        main_window.on_reset_token(move || {
            let dev_id = {
                let s = state_clone.lock().unwrap();
                s.current_device_id.clone()
            };
            if let Some(dev_id) = dev_id {
                let window_clone = window_weak.clone();
                thread::spawn(move || {
                    let fido = FidoKeyManager::new();
                    let result = fido.reset_token(&dev_id);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = window_clone.upgrade() {
                            match result {
                                Ok(_) => ui.set_status_message(SharedString::from("Hardware completely reset.")),
                                Err(e) => ui.set_status_message(SharedString::from(format!("Hardware error: {}", e))),
                            }
                        }
                    });
                });
            }
        });
    }

    main_window.invoke_refresh_devices();
    main_window.run()
}