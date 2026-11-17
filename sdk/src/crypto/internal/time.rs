// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use chrono::{DateTime, Utc};
use time::OffsetDateTime;

/// Return the current time in UTC, including on browser WebAssembly.
pub(crate) fn now() -> OffsetDateTime {
    #[cfg(not(target_arch = "wasm32"))]
    {
        OffsetDateTime::now_utc()
    }

    #[cfg(target_arch = "wasm32")]
    {
        let duration = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO);

        OffsetDateTime::UNIX_EPOCH + duration
    }
}

/// RFC 3339 serialization with the SDK's existing 0/3/6/9 fractional digits.
pub(crate) mod rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::{format_description::well_known::Rfc3339, OffsetDateTime};

    pub(crate) fn serialize<S: Serializer>(
        timestamp: &OffsetDateTime,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format(*timestamp).map_err(serde::ser::Error::custom)?)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<OffsetDateTime, D::Error> {
        let value = String::deserialize(deserializer)?;

        parse(&value)
    }

    fn parse<E: serde::de::Error>(value: &str) -> Result<OffsetDateTime, E> {
        // `time` otherwise silently clamps leap seconds to 59.999999999.
        if value.as_bytes().get(17..19) == Some(b"60") {
            return Err(E::custom("leap-second timestamps are not supported"));
        }

        OffsetDateTime::parse(value, &Rfc3339).map_err(E::custom)
    }

    fn format(timestamp: OffsetDateTime) -> Result<String, time::error::Format> {
        let mut value = timestamp.format(&Rfc3339)?;

        if let Some(dot) = value.find('.') {
            let digits = value[dot + 1..]
                .bytes()
                .take_while(u8::is_ascii_digit)
                .count();
            let padding = (3 - digits % 3) % 3;
            value.insert_str(dot + 1 + digits, &"00"[..padding]);
        }

        Ok(value)
    }

    pub(crate) mod option {
        use serde::{Deserialize, Deserializer, Serializer};
        use time::OffsetDateTime;

        use crate::crypto::internal::time::rfc3339::{format, parse};

        pub(crate) fn serialize<S: Serializer>(
            timestamp: &Option<OffsetDateTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match timestamp {
                Some(timestamp) => serializer
                    .serialize_some(&format(*timestamp).map_err(serde::ser::Error::custom)?),
                None => serializer.serialize_none(),
            }
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<OffsetDateTime>, D::Error> {
            Option::<String>::deserialize(deserializer)?
                .map(|value| parse(&value))
                .transpose()
        }
    }
}

/// Return the current time in UTC.
pub(crate) fn utc_now() -> DateTime<Utc> {
    std::time::SystemTime::from(now()).into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::crypto::internal::time;

    #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
    struct Timestamp {
        #[serde(with = "super::rfc3339")]
        value: ::time::OffsetDateTime,
        #[serde(default, with = "super::rfc3339::option")]
        optional: Option<::time::OffsetDateTime>,
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn rfc3339_preserves_existing_wire_format() {
        for value in [
            "1969-12-31T23:59:59Z",
            "1970-01-01T00:00:00Z",
            "2000-02-29T12:34:56.100Z",
            "2024-05-27T08:40:39.569856Z",
            "2024-05-27T08:40:39.000000001Z",
            "2024-05-27T08:40:39.120Z",
            "2024-05-27T08:40:39.123400+05:30",
            "2024-05-27T08:40:39-07:00",
            "9999-12-31T23:59:59Z",
        ] {
            let json = serde_json::json!({ "value": value, "optional": value });
            let timestamp: Timestamp = serde_json::from_value(json.clone()).unwrap();

            assert_eq!(serde_json::to_value(timestamp).unwrap(), json, "{value}");
        }
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn rfc3339_validates_and_normalizes_timestamps() {
        for (input, expected) in [
            ("2024-05-27T08:40:39+00:00", "2024-05-27T08:40:39Z"),
            ("2024-05-27T08:40:39.1Z", "2024-05-27T08:40:39.100Z"),
            ("2024-05-27T08:40:39.0001Z", "2024-05-27T08:40:39.000100Z"),
        ] {
            let timestamp: Timestamp =
                serde_json::from_value(serde_json::json!({ "value": input })).unwrap();
            let serialized = serde_json::to_value(timestamp).unwrap();

            assert_eq!(serialized["value"], expected);
            assert!(serialized["optional"].is_null());
        }

        for value in [
            "2023-02-29T00:00:00Z",
            "2024-01-01T00:00:00",
            "2024-01-01T24:00:00Z",
            "2016-12-31T23:59:60Z",
            "2016-12-31T23:59:60.5Z",
            "2017-01-01T05:29:60+05:30",
        ] {
            assert!(
                serde_json::from_value::<Timestamp>(serde_json::json!({ "value": value })).is_err()
            );
            assert!(serde_json::from_value::<Timestamp>(serde_json::json!({
                "value": "2024-01-01T00:00:00Z",
                "optional": value,
            }))
            .is_err());
        }
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn now() {
        let time_now = time::utc_now();
        let unix_ts = time_now.timestamp();
        dbg!(&unix_ts);

        assert!(unix_ts > 1731560000); // 2024-11-14T04:53:00Z
    }
}
