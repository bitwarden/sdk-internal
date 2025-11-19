use bitwarden_core::DeviceType;

/// Custom headers used in login requests to the connect/token endpoint
/// - distinct from standard HTTP headers available in `reqwest::header`.
#[derive(Debug, Clone)]
pub enum LoginRequestHeader {
    /// The "Device-Type" header indicates the type of device making the request.
    DeviceType(DeviceType),
}

impl LoginRequestHeader {
    /// Returns the header name as a string.
    pub fn header_name(&self) -> &'static str {
        match self {
            Self::DeviceType(_) => "Device-Type",
        }
    }

    /// Returns the header value as a string.
    pub fn header_value(&self) -> String {
        match self {
            Self::DeviceType(device_type) => (*device_type as u8).to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_type_header_name() {
        let header = LoginRequestHeader::DeviceType(DeviceType::SDK);
        assert_eq!(header.header_name(), "Device-Type");
    }

    #[test]
    fn test_device_type_header_value() {
        let header = LoginRequestHeader::DeviceType(DeviceType::SDK);
        assert_eq!(header.header_value(), "21");
    }

    #[test]
    fn test_device_type_header_value_android() {
        let header = LoginRequestHeader::DeviceType(DeviceType::Android);
        assert_eq!(header.header_value(), "0");
    }

    #[test]
    fn test_device_type_header_value_mac_os_cli() {
        let header = LoginRequestHeader::DeviceType(DeviceType::MacOsCLI);
        assert_eq!(header.header_value(), "24");
    }
}
