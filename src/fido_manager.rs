use crate::models::{DeviceCapabilities, DeviceDescriptor, FingerprintRecord, PasskeyRecord};
use anyhow::{bail, Result};
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory, get_fidokey_devices};
use ctap_hid_fido2::public_key_credential_descriptor::PublicKeyCredentialDescriptor;

pub struct FidoKeyManager {}

impl Default for FidoKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FidoKeyManager {
    pub fn new() -> Self {
        Self {}
    }

    fn get_device_handle(&self, device_id: &str) -> Result<ctap_hid_fido2::FidoKeyHid> {
        let devices = get_fidokey_devices();
        for dev in devices {
            if dev.info == device_id {
                let mut cfg = Cfg::init();
                cfg.use_pre_credential_management = true; 
                let key = FidoKeyHidFactory::create_by_params(&[dev.param], &cfg)?;
                return Ok(key);
            }
        }
        bail!("FIDO2 device was not found or is disconnected.");
    }

    pub fn enumerate_devices(&self) -> Result<Vec<DeviceDescriptor>> {
        let mut devices = Vec::new();
        let hid_devices = get_fidokey_devices();
        
        for dev in hid_devices.into_iter() {
            let display_name = if dev.product_string.is_empty() {
                "Unknown FIDO2 Security Key".to_string()
            } else {
                dev.product_string.clone()
            };

            devices.push(DeviceDescriptor {
                raw_id: dev.info.clone(),
                display_name,
            });
        }
        Ok(devices)
    }

    pub fn get_pin_retries(&self, device_id: &str) -> Result<i32> {
        let device = self.get_device_handle(device_id)?;
        let retries = device.get_pin_retries()?;
        Ok(retries)
    }

    pub fn inspect_device(&self, device_id: &str, pin: &str) -> Result<DeviceCapabilities> {
        let device = self.get_device_handle(device_id)?;
        let mut caps = DeviceCapabilities::default();
        
        let info = device.get_info()?;
        caps.supports_fido2_1 = info.versions.contains(&"FIDO_2_1".to_string());
        
        for (key, val) in &info.options {
            if key == "bioEnroll" {
                caps.supports_bio_enroll = *val;
            }
        }

        let hex_aaguid = hex::encode(&info.aaguid);
        let formatted_aaguid = if hex_aaguid.len() == 32 {
            format!("{}-{}-{}-{}-{}", &hex_aaguid[0..8], &hex_aaguid[8..12], &hex_aaguid[12..16], &hex_aaguid[16..20], &hex_aaguid[20..32])
        } else {
            hex_aaguid
        };

        caps.raw_info.push(("AAGUID".to_string(), formatted_aaguid));
        caps.raw_info.push(("Firmware Version".to_string(), info.firmware_version.to_string()));
        caps.raw_info.push(("FIDO Versions".to_string(), info.versions.join(", ")));
        caps.raw_info.push(("Supported Transports".to_string(), info.transports.join(", ")));
        caps.raw_info.push(("Extensions".to_string(), info.extensions.join(", ")));
        caps.raw_info.push(("Max Message Size".to_string(), format!("{} bytes", info.max_msg_size)));
        caps.raw_info.push(("Max Credential ID Length".to_string(), format!("{} bytes", info.max_credential_id_length)));
        caps.raw_info.push(("Max Credentials in List".to_string(), info.max_credential_count_in_list.to_string()));
        
        let mut algs = Vec::new();
        for (k, v) in &info.algorithms {
            if k == "alg" {
                algs.push(match v.as_str() {
                    "-7" => "ES256",
                    "-8" => "EdDSA",
                    "-25" => "ECDH-ES + HKDF-256",
                    "-35" => "ES384",
                    "-36" => "ES512",
                    _ => v.as_str()
                }.to_string());
            }
        }
        caps.raw_info.push(("Supported Algorithms".to_string(), algs.join(", ")));

        let pin_uv: Vec<String> = info.pin_uv_auth_protocols.iter().map(|p| p.to_string()).collect();
        caps.raw_info.push(("PIN/UV Auth Protocols".to_string(), pin_uv.join(", ")));

        let get_opt = |k: &str| info.options.iter().find(|(key, _)| key == k).map(|(_, v)| *v);
        
        caps.raw_info.push(("User Presence (up)".to_string(), get_opt("up").unwrap_or(false).to_string()));
        caps.raw_info.push(("Platform Authenticator (plat)".to_string(), get_opt("plat").unwrap_or(false).to_string()));
        caps.raw_info.push(("Credential Management (credMgmt)".to_string(), get_opt("credMgmt").unwrap_or(false).to_string()));
        caps.raw_info.push(("Large Blobs (largeBlobs)".to_string(), get_opt("largeBlobs").unwrap_or(false).to_string()));
        caps.raw_info.push(("PIN/UV Auth Token (pinUvAuthToken)".to_string(), get_opt("pinUvAuthToken").unwrap_or(false).to_string()));
        caps.raw_info.push(("Make Cred W/O UV (makeCredUvNotRqd)".to_string(), get_opt("makeCredUvNotRqd").unwrap_or(false).to_string()));

        if let Ok(creds_meta) = device.credential_management_get_creds_metadata(Some(pin)) {
            caps.raw_info.push(("Saved Passkeys".to_string(), creds_meta.existing_resident_credentials_count.to_string()));
            caps.raw_info.push(("Remaining Space (Passkeys)".to_string(), creds_meta.max_possible_remaining_resident_credentials_count.to_string()));
        }

        caps.settings_info.push(("Always-UV Required (alwaysUv)".to_string(), if get_opt("alwaysUv").unwrap_or(false) { "Enabled" } else { "Disabled" }.to_string()));
        caps.settings_info.push(("Set Min PIN Length (setMinPINLength)".to_string(), if get_opt("setMinPINLength").unwrap_or(false) { "Supported" } else { "Unsupported" }.to_string()));
        caps.settings_info.push(("Current Min PIN Length".to_string(), info.min_pin_length.to_string()));
        caps.settings_info.push(("Force PIN Change".to_string(), if info.force_pin_change { "Yes" } else { "No" }.to_string()));
        caps.settings_info.push(("Client PIN (clientPin)".to_string(), if get_opt("clientPin").unwrap_or(false) { "Configured" } else { "Unconfigured" }.to_string()));
        caps.settings_info.push(("Biometrics Enrolled (bioEnroll)".to_string(), if get_opt("bioEnroll").unwrap_or(false) { "Yes" } else { "No" }.to_string()));
        if let Ok(uv_retries) = device.get_uv_retries() {
            caps.settings_info.push(("UV Retries Remaining".to_string(), uv_retries.to_string()));
        }

        Ok(caps)
    }

    pub fn list_passkeys(&self, device_id: &str, pin: &str) -> Result<Vec<PasskeyRecord>> {
        let device = self.get_device_handle(device_id)?;
        let mut records = Vec::new();

        let rps = device.credential_management_enumerate_rps(Some(pin))?;
        for rp in rps {
            let creds = device.credential_management_enumerate_credentials(Some(pin), &rp.rpid_hash)?;
            for cred in creds {
                let protection_str = format!("{:?}", cred.cred_protect);
                let domain = if rp.public_key_credential_rp_entity.id.is_empty() {
                    rp.public_key_credential_rp_entity.name.clone()
                } else {
                    rp.public_key_credential_rp_entity.id.clone()
                };
                
                records.push(PasskeyRecord {
                    credential_id: hex::encode(&cred.public_key_credential_descriptor.id),
                    user: cred.public_key_credential_user_entity.name.clone(),
                    user_id: hex::encode(&cred.public_key_credential_user_entity.id),
                    display_name: cred.public_key_credential_user_entity.display_name.clone(),
                    domain,
                    protection: protection_str,
                });
            }
        }
        Ok(records)
    }

    pub fn list_fingerprints(&self, device_id: &str, pin: &str) -> Result<Vec<FingerprintRecord>> {
        let device = self.get_device_handle(device_id)?;
        let mut records = Vec::new();

        let templates = device.bio_enrollment_enumerate_enrollments(pin)?;
        for template in templates {
            records.push(FingerprintRecord {
                index: hex::encode(&template.template_id),
                description: template.template_friendly_name.unwrap_or_else(|| "Unnamed Fingerprint".to_string()),
            });
        }
        Ok(records)
    }
    
    pub fn delete_passkey(&self, device_id: &str, pin: &str, credential_id_hex: &str) -> Result<()> {
        let device = self.get_device_handle(device_id)?;
        let cred_id_bytes = hex::decode(credential_id_hex)?;
        
        let mut pkcd = PublicKeyCredentialDescriptor::default();
        pkcd.id = cred_id_bytes;
        pkcd.ctype = "public-key".to_string(); 

        device.credential_management_delete_credential(Some(pin), pkcd)?;
        Ok(())
    }
    
    pub fn add_fingerprint(&self, device_id: &str, pin: &str) -> Result<()> {
        let device = self.get_device_handle(device_id)?;
        let (enroll_status1, _) = device.bio_enrollment_begin(pin, Some(10000))?;
        
        for _ in 0..10 {
            let status2 = device.bio_enrollment_next(&enroll_status1, Some(10000))?;
            if status2.is_finish {
                break;
            }
        }
        Ok(())
    }

    pub fn rename_fingerprint(&self, device_id: &str, pin: &str, template_id_hex: &str, friendly_name: &str) -> Result<()> {
        let device = self.get_device_handle(device_id)?;
        let template_id_bytes = hex::decode(template_id_hex)?;
        device.bio_enrollment_set_friendly_name(pin, &template_id_bytes, friendly_name)?;
        Ok(())
    }

    pub fn delete_fingerprint(&self, device_id: &str, pin: &str, template_id_hex: &str) -> Result<()> {
        let device = self.get_device_handle(device_id)?;
        let template_id_bytes = hex::decode(template_id_hex)?;
        
        device.bio_enrollment_remove(pin, &template_id_bytes)?;
        Ok(())
    }

    pub fn change_pin(&self, device_id: &str, old_pin: &str, new_pin: &str) -> Result<()> {
        let device = self.get_device_handle(device_id)?;
        device.change_pin(old_pin, new_pin)?;
        Ok(())
    }

    pub fn enforce_uv(&self, device_id: &str, pin: &str) -> Result<()> {
        let device = self.get_device_handle(device_id)?;
        device.toggle_always_uv(Some(pin))?;
        Ok(())
    }

    pub fn get_uv_retries(&self, device_id: &str) -> Result<i32> {
        let device = self.get_device_handle(device_id)?;
        Ok(device.get_uv_retries()?)
    }

    pub fn wink(&self, device_id: &str) -> Result<()> {
        let device = self.get_device_handle(device_id)?;
        device.wink()?;
        Ok(())
    }

    pub fn wait_for_touch(&self, device_id: &str) -> Result<()> {
        let device = self.get_device_handle(device_id)?;
        match device.selection() {
            Ok(_) => Ok(()),
            Err(e) => bail!("Physical touch command failed or unsupported: {}", e),
        }
    }

    pub fn reset_token(&self, _device_id: &str) -> Result<()> {
        bail!("The ctap-hid-fido2 package (v3.5) lacks an official implementation for the `authenticatorReset` (0x07) command.");
    }
} 