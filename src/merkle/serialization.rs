use std::time::{SystemTime, Duration};
use serde::{Deserialize, Deserializer, Serializer};

// For Instant serialization, we need to convert to SystemTime
pub mod timestamp_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::SystemTime;
    use std::time::Duration;

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let timestamp = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        serializer.serialize_u64(timestamp)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let timestamp = u64::deserialize(deserializer)?;
        Ok(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp))
    }
}
