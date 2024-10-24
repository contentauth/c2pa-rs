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

use serde::Deserialize;

pub(crate) mod one_or_many {
    use std::{fmt, marker::PhantomData};

    use nonempty_collections::{nev, NEVec};
    use serde::{de, Deserialize, Deserializer, Serialize};

    pub fn serialize<T: Serialize, S>(value: &NEVec<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match value.split_first() {
            (first, []) => first.serialize(serializer),
            _ => {
                let mut refs: Vec<&T> = vec![];
                for t in value {
                    refs.push(t);
                }
                refs.serialize(serializer)
            }
        }
    }

    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<NEVec<T>, D::Error> {
        deserializer.deserialize_any(Visitor(PhantomData))
    }

    struct Visitor<T>(PhantomData<T>);

    impl<'de, T> de::Visitor<'de> for Visitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = NEVec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("array or map")
        }

        fn visit_map<M>(self, map: M) -> Result<NEVec<T>, M::Error>
        where
            M: de::MapAccess<'de>,
        {
            eprintln!("Yo!");

            let one = Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))?;

            Ok(nev!(one))
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))
        }
    }
}

pub(crate) fn not_null<'de, T: Deserialize<'de>, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}
