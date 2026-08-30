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

//! Tag source for the single-copy case.

use super::SharedCounter;

/// The tag every registry claims when nothing coordinates across copies.
pub(crate) const LOCAL_TAG: u16 = 0;

/// Hands out [`LOCAL_TAG`] without coordinating with anything.
///
/// Correct whenever one copy of this crate is loaded, which is the usual case.
/// With two copies both claim tag 0, so neither can recognise the other's
/// handles and a foreign handle is reported as untracked — the behavior before
/// tags existed. Distinguishing them needs a counter shared across copies.
pub(crate) struct LocalCounter;

impl SharedCounter for LocalCounter {
    fn claim_tag(&self) -> u16 {
        LOCAL_TAG
    }
}
