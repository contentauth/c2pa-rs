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

use time::OffsetDateTime;

/// Return the current time in UTC.
pub(crate) fn utc_now() -> OffsetDateTime {
    #[cfg(not(target_arch = "wasm32"))]
    {
        OffsetDateTime::now_utc()
    }

    #[cfg(target_arch = "wasm32")]
    {
        // Very unlikely that SystemTime would be before Unix epoch, but if so, cap it
        // at 0.
        let utc_duration = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO);

        OffsetDateTime::UNIX_EPOCH + utc_duration
    }
}

/// Format report timestamps with an explicit offset and 0/3/6/9 fractional digits.
pub(crate) fn format_with_offset(timestamp: OffsetDateTime) -> String {
    let year = timestamp.year();
    let year = if year < 0 {
        format!("-{:04}", year.unsigned_abs())
    } else {
        format!("{year:04}")
    };
    let mut formatted = format!(
        "{year}-{:02}-{:02}T{:02}:{:02}:{:02}",
        timestamp.month() as u8,
        timestamp.day(),
        timestamp.hour(),
        timestamp.minute(),
        timestamp.second(),
    );

    let nanoseconds = timestamp.nanosecond();

    if nanoseconds != 0 {
        if nanoseconds.is_multiple_of(1_000_000) {
            formatted.push_str(&format!(".{:03}", nanoseconds / 1_000_000));
        } else if nanoseconds.is_multiple_of(1_000) {
            formatted.push_str(&format!(".{:06}", nanoseconds / 1_000));
        } else {
            formatted.push_str(&format!(".{nanoseconds:09}"));
        }
    }

    // Match the former formatter's nearest-minute rounding, ties away from zero.
    let offset = timestamp.offset();
    let minutes = (offset.whole_seconds().unsigned_abs() + 30) / 60;
    formatted.push(if offset.is_negative() { '-' } else { '+' });
    formatted.push_str(&format!("{:02}:{:02}", minutes / 60, minutes % 60));

    formatted
}

/// RFC 3339 serde preserving the SDK's timestamp spelling and fractional precision.
pub(crate) mod rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::{format_description::well_known::Rfc3339, OffsetDateTime};

    use crate::crypto::internal;

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
        if !(0..10_000).contains(&timestamp.year()) {
            return Err(time::error::Format::InvalidComponent("year"));
        }

        let mut value = internal::time::format_with_offset(timestamp);

        if timestamp.offset().is_utc() {
            value.truncate(value.len() - 6);
            value.push('Z');
        }

        Ok(value)
    }

    pub(crate) mod option {
        use serde::{Deserialize, Deserializer, Serializer};
        use time::OffsetDateTime;

        use crate::crypto::internal;

        pub(crate) fn serialize<S: Serializer>(
            timestamp: &Option<OffsetDateTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match timestamp {
                Some(timestamp) => serializer.serialize_some(
                    &internal::time::rfc3339::format(*timestamp)
                        .map_err(serde::ser::Error::custom)?,
                ),
                None => serializer.serialize_none(),
            }
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<OffsetDateTime>, D::Error> {
            Option::<String>::deserialize(deserializer)?
                .map(|value| internal::time::rfc3339::parse(&value))
                .transpose()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::crypto::internal;

    #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
    struct Timestamp {
        #[serde(with = "internal::time::rfc3339")]
        value: time::OffsetDateTime,
        #[serde(default, with = "internal::time::rfc3339::option")]
        optional: Option<time::OffsetDateTime>,
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn report_offsets_and_fractional_precision_are_preserved() {
        for (seconds, local, offset) in [
            (0, "1970-01-01T00:00:00", "+00:00"),
            (29, "1970-01-01T00:00:29", "+00:00"),
            (30, "1970-01-01T00:00:30", "+00:01"),
            (90, "1970-01-01T00:01:30", "+00:02"),
            (-29, "1969-12-31T23:59:31", "-00:00"),
            (-30, "1969-12-31T23:59:30", "-00:01"),
            (-90, "1969-12-31T23:58:30", "-00:02"),
            (19_800, "1970-01-01T05:30:00", "+05:30"),
            (-25_200, "1969-12-31T17:00:00", "-07:00"),
        ] {
            for (nanoseconds, fraction) in [
                (0, ""),
                (100_000_000, ".100"),
                (123_400_000, ".123400"),
                (123_456_789, ".123456789"),
            ] {
                let timestamp = time::OffsetDateTime::UNIX_EPOCH
                    .replace_nanosecond(nanoseconds)
                    .unwrap()
                    .to_offset(time::UtcOffset::from_whole_seconds(seconds).unwrap());

                assert_eq!(
                    internal::time::format_with_offset(timestamp),
                    format!("{local}{fraction}{offset}"),
                    "offset {seconds}, nanoseconds {nanoseconds}"
                );

                let timestamp = Timestamp {
                    value: timestamp,
                    optional: Some(timestamp),
                };
                let expected = if seconds == 0 {
                    format!("{local}{fraction}Z")
                } else {
                    format!("{local}{fraction}{offset}")
                };
                let serialized = serde_json::to_value(timestamp).unwrap();

                assert_eq!(serialized["value"], expected);
                assert_eq!(serialized["optional"], expected);
            }
        }
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn identity_json_retains_timestamp_spelling() {
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
    fn identity_json_validates_dates_and_rejects_leap_seconds() {
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
        let time_now = internal::time::utc_now();
        let unix_ts = time_now.unix_timestamp();
        dbg!(&unix_ts);

        assert!(unix_ts > 1731560000); // 2024-11-14T04:53:00Z
    }
}
