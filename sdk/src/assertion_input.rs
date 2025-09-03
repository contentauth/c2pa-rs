// In assertion_input.rs
use crate::Result;
//use serde::{Serialize};
use serde_json::Value as JsonValue;
use serde_cbor::Value as CborValue;
use crate::assertion::AssertionBase;

pub trait AssertionInput {
    fn to_assertion_with_label(self, label: &str) -> Result<Box<dyn AssertionBase>>;
}

// Implementation for JSON values
impl AssertionInput for JsonValue {
    fn to_assertion_with_label(self, label: &str) ->  Result<Box<dyn AssertionBase>> {
        try_deserialize_known_json_assertion(label, &self)
    }
}

// Implementation for CBOR values
impl AssertionInput for CborValue {
    fn to_assertion_with_label(self, label: &str) ->  Result<Box<dyn AssertionBase>> {
        try_deserialize_known_cbor_assertion(label, &self)
    }
}

// Implementation for strings
impl AssertionInput for &str {
    fn to_assertion_with_label(self, label: &str) ->  Result<Box<dyn AssertionBase>> {
        let json_value: JsonValue = serde_json::from_str(self)?;
        json_value.to_assertion_with_label(label)
    }
}

impl AssertionInput for String {
    fn to_assertion_with_label(self, label: &str) ->  Result<Box<dyn AssertionBase>> {
        self.as_str().to_assertion_with_label(label)
    }
}


// Helper functions - return concrete Assertion
fn try_deserialize_known_json_assertion(label: &str, value: &JsonValue) -> Result<Box<dyn AssertionBase>> {
    match label {
        crate::assertions::Actions::LABEL => {
            let actions: crate::assertions::Actions = serde_json::from_value(value.clone())?;
            Ok(Box::new(actions)) // Convert to concrete Assertion
        },
        // crate::assertions::Ingredient::LABEL => {
        //     let ingredient: crate::assertions::Ingredient = serde_json::from_value(value.clone())?;
        //     ingredient.to_assertion() // Convert to concrete Assertion
        // },
        // Add more known assertion types here as needed
        _ => {
            // Create a User assertion for unknown types
            let json_str = serde_json::to_string(value)?;
            let user_json = crate::assertions::User::new(label, &json_str);
            Ok(Box::new(user_json))
        }
    }
}

fn try_deserialize_known_cbor_assertion(label: &str, value: &CborValue) ->  Result<Box<dyn AssertionBase>> {
    let cbor_bytes = serde_cbor::to_vec(value)?;
    
    match label {
        crate::assertions::Actions::LABEL => {
            let actions: crate::assertions::Actions = serde_cbor::from_slice(&cbor_bytes)?;
            Ok(Box::new(actions)) // Convert to concrete Assertion
        },
        // crate::assertions::Ingredient::LABEL => {
        //     let ingredient: crate::assertions::Ingredient = serde_cbor::from_slice(&cbor_bytes)?;
        //     ingredient.to_assertion() // Convert to concrete Assertion
        // },
        // Add more known assertion types here as needed
        _ => {
            // Create a UserCbor assertion for unknown types
            let user_cbor = crate::assertions::UserCbor::new(label, cbor_bytes);
            Ok(Box::new(user_cbor))
        }
    }
}