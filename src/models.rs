#[derive(Debug, Clone, Default)]
pub struct DeviceDescriptor {
    pub raw_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Default)]
pub struct PasskeyRecord {
    pub credential_id: String,
    pub user: String,
    pub user_id: String,
    pub display_name: String,
    pub domain: String,
    pub protection: String,
}

#[derive(Debug, Clone, Default)]
pub struct FingerprintRecord {
    pub index: String,
    pub description: String,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceCapabilities {
    pub supports_fido2_1: bool,
    pub supports_bio_enroll: bool,
    pub raw_info: Vec<(String, String)>,
    pub settings_info: Vec<(String, String)>,
}