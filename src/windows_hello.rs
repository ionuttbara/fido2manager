use anyhow::{bail, Result};
use windows::core::HSTRING;
use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};

pub struct WindowsHelloManager;

impl WindowsHelloManager {
    pub fn new() -> Self {
        Self
    }

    /// Triggers the native Windows Hello biometric / PIN verification dialog.
    pub fn verify_user_presence(&self, message: &str) -> Result<bool> {
        // (Certain) UserConsentVerifier uses the native OS-level Hello prompt.
        let msg = HSTRING::from(message);
        let async_op = UserConsentVerifier::RequestVerificationAsync(&msg)?;
        let result = async_op.get()?;

        match result {
            UserConsentVerificationResult::Verified => Ok(true),
            UserConsentVerificationResult::Canceled => Ok(false),
            UserConsentVerificationResult::DeviceNotPresent => {
                bail!("Windows Hello device is not configured on this machine.");
            }
            UserConsentVerificationResult::NotConfiguredForUser => {
                bail!("Windows Hello is not set up for the current user profile.");
            }
            UserConsentVerificationResult::DisabledByPolicy => {
                bail!("Windows Hello authentication is disabled by system policy.");
            }
            UserConsentVerificationResult::DeviceBusy => {
                bail!("The biometric/security key authentication hardware is currently busy.");
            }
            _ => Ok(false),
        }
    }
}