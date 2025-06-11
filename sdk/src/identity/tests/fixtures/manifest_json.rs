// Copyright 2025 Adobe. All rights reserved.
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

use serde_json::json;

/// Boilerplate JSON to use when building manifests for test cases.
pub(crate) fn manifest_json() -> String {
    json!({
        "vendor": "test",
        "claim_generator_info": [
            {
                "name": "c2pa_test",
                "version": "1.0.0"
            }
        ],
        "metadata": [
            {
                "dateTime": "1985-04-12T23:20:50.52Z",
                "my_custom_metadata": "my custom metatdata value"
            }
        ],
        "title": "Test_Manifest",
        "format": "image/tiff",
        "instance_id": "1234",
        "thumbnail": {
            "format": "image/jpeg",
            "identifier": "thumbnail.jpg"
        },
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.opened",
                            "parameters": {
                                "org.cai.ingredientIds": ["12345"]
                            }
                        }
                    ]
                }
            },
            {
                "label": "cawg.metadata",
                // DO NOT CHECK IN: Q&D hack for Eric's demo.
                "data": {
                    "@context": {
                        "dc": "http://purl.org/dc/elements/1.1/",
                        "exif": "http://ns.adobe.com/exif/1.0/",
                        "photoshop" : "http://ns.adobe.com/photoshop/1.0/",
                    },
                    "dc:description": "Champaign County, Illinois, 1995",
                    "dc:rights": "Copyright © 1995, Eric Scouten",
                    "dc:title": "Country Road at Sunset",
                    "exif:DateTimeOriginal": "1995-08-21T18:07:01-05:00",
                    "exif:DateTimeDigitized": "2007-04-26T08:25:32Z",
                    "exif:GPSLatitude": "40,1.9408N",
                    "exif:GPSLongitude": "88,7.0331W",
                    "photoshop:City": "Champaign County",
                    "photoshop:Country": "United States",
                    "photoshop:State": "Illinois",
                }
            }
        ]
    })
    .to_string()
}

pub(crate) fn parent_json() -> String {
    json!({
        "title": "Parent Test",
        "format": "image/jpeg",
        "instance_id": "12345",
        "relationship": "parentOf"
    })
    .to_string()
}
