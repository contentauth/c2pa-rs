// Copyright 2022 Adobe. All rights reserved.
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

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{labels, AssertionMetadata, AssetType};
use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    error::Result,
};

pub enum AssetTypeEnum {
    Classifier,
    Cluster,
    Dataset,
    DatasetJax,
    DatasetKeras,
    DatasetMlNet,
    DatasetMxNet,
    DatasetOnnx,
    DatasetOpenVino,
    DatasetPyTorch,
    DatasetTensoflow,
    FormatNumpy,
    FormatProtoBuf,
    FormatPickle,
    Generator,
    GeneratorPrompt,
    GeneratorSeed,
    Model,
    ModelJax,
    ModelKeras,
    ModelMlNet,
    ModelMxNet,
    ModelOnnx,
    ModelOpenVino,
    ModelOpenVinoParameter,
    ModelOpenVinoTopology,
    ModelPyTorch,
    ModelTensorflow,
    Regressor,
    TensorflowHubModule,
    TensorflowSaveModel,
    AuditLog,
    ModelCaffe,
    ModelCaffe2,
    ModelCatBoost,
    ModelCoreMl,
    ModelFlax,
    ModelHuggingFaceTransformers,
    ModelLightGbm,
    ModelPaddle,
    ModelSklearn,
    ModelTensorRt,
    ModelTfLite,
    ModelTorchScript,
    ModelXgBoost,
    VersionHistory,
    Other(String),
}

impl From<AssetTypeEnum> for String {
    fn from(val: AssetTypeEnum) -> String {
        match val {
            AssetTypeEnum::Classifier => "c2pa.types.classifier".into(),
            AssetTypeEnum::Cluster => "c2pa.types.cluster".into(),
            AssetTypeEnum::Dataset => "c2pa.types.dataset".into(),
            AssetTypeEnum::DatasetJax => "c2pa.types.dataset.jax".into(),
            AssetTypeEnum::DatasetKeras => "c2pa.types.dataset.keras".into(),
            AssetTypeEnum::DatasetMlNet => "c2pa.types.dataset.ml_net".into(),
            AssetTypeEnum::DatasetMxNet => "c2pa.types.dataset.mxnet".into(),
            AssetTypeEnum::DatasetOnnx => "c2pa.types.dataset.onnx".into(),
            AssetTypeEnum::DatasetOpenVino => "c2pa.types.dataset.openvino".into(),
            AssetTypeEnum::DatasetPyTorch => "c2pa.types.dataset.pytorch".into(),
            AssetTypeEnum::DatasetTensoflow => "c2pa.types.dataset.tensorflow".into(),
            AssetTypeEnum::FormatNumpy => "c2pa.types.format.numpy".into(),
            AssetTypeEnum::FormatProtoBuf => "c2pa.types.format.protobuf".into(),
            AssetTypeEnum::FormatPickle => "c2pa.types.format.pickle".into(),
            AssetTypeEnum::Generator => "c2pa.types.generator".into(),
            AssetTypeEnum::GeneratorPrompt => "c2pa.types.generator.prompt".into(),
            AssetTypeEnum::GeneratorSeed => "c2pa.types.generator.seed".into(),
            AssetTypeEnum::Model => "c2pa.types.model".into(),
            AssetTypeEnum::ModelJax => "c2pa.types.model.jax".into(),
            AssetTypeEnum::ModelKeras => "c2pa.types.model.keras".into(),
            AssetTypeEnum::ModelMlNet => "c2pa.types.model.ml_net".into(),
            AssetTypeEnum::ModelMxNet => "c2pa.types.model.mxnet".into(),
            AssetTypeEnum::ModelOnnx => "c2pa.types.model.onnx".into(),
            AssetTypeEnum::ModelOpenVino => "c2pa.types.model.openvino".into(),
            AssetTypeEnum::ModelOpenVinoParameter => "c2pa.types.model.openvino.parameter".into(),
            AssetTypeEnum::ModelOpenVinoTopology => "c2pa.types.model.openvino.topology".into(),
            AssetTypeEnum::ModelPyTorch => "c2pa.types.model.pytorch".into(),
            AssetTypeEnum::ModelTensorflow => "c2pa.types.model.tensorflow".into(),
            AssetTypeEnum::Regressor => "c2pa.types.regressor".into(),
            AssetTypeEnum::TensorflowHubModule => "c2pa.types.tensorflow.hubmodule".into(),
            AssetTypeEnum::TensorflowSaveModel => "c2pa.types.tensorflow.savedmodel".into(),
            AssetTypeEnum::AuditLog => "c2pa.types.audit-log".into(),
            AssetTypeEnum::ModelCaffe => "c2pa.types.model.caffe".into(),
            AssetTypeEnum::ModelCaffe2 => "c2pa.types.model.caffe2".into(),
            AssetTypeEnum::ModelCatBoost => "c2pa.types.model.catboost".into(),
            AssetTypeEnum::ModelCoreMl => "c2pa.types.model.coreml".into(),
            AssetTypeEnum::ModelFlax => "c2pa.types.model.flax".into(),
            AssetTypeEnum::ModelHuggingFaceTransformers => {
                "c2pa.types.model.huggingface.transformers".into()
            }
            AssetTypeEnum::ModelLightGbm => "c2pa.types.model.lightgbm".into(),
            AssetTypeEnum::ModelPaddle => "c2pa.types.model.paddle".into(),
            AssetTypeEnum::ModelSklearn => "c2pa.types.model.sklearn".into(),
            AssetTypeEnum::ModelTensorRt => "c2pa.types.model.tensorrt".into(),
            AssetTypeEnum::ModelTfLite => "c2pa.types.model.tflite".into(),
            AssetTypeEnum::ModelTorchScript => "c2pa.types.model.torchscript".into(),
            AssetTypeEnum::ModelXgBoost => "c2pa.types.model.xgboost".into(),
            AssetTypeEnum::VersionHistory => "c2pa.types.version-history".into(),
            AssetTypeEnum::Other(v) => v,
        }
    }
}

/// `c2pa.asset-type.v2`, which adds `dc:format`. Version 1 (`c2pa.asset-type`) is deprecated
/// but still read: its fields are a subset of version 2's.
const ASSERTION_CREATION_VERSION: usize = 2;

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct AssetTypes {
    /// The asset's IANA media type, such as `text/csv`.
    #[serde(rename = "dc:format", skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    types: Vec<AssetType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<AssertionMetadata>,
}

#[allow(dead_code)]
impl AssetTypes {
    /// The base label. Assertions are written as `c2pa.asset-type.v2`.
    ///
    /// See [Asset type - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_asset_type).
    pub const LABEL: &'static str = labels::ASSET_TYPE;

    pub fn new(at: AssetType) -> Self {
        AssetTypes {
            format: None,
            types: vec![at],
            metadata: None,
        }
    }

    /// Creates an asset type assertion holding only the asset's IANA media type.
    pub fn from_format<S: Into<String>>(format: S) -> Self {
        AssetTypes {
            format: Some(format.into()),
            types: Vec::new(),
            metadata: None,
        }
    }

    /// Sets the asset's IANA media type (`dc:format`).
    pub fn set_format<S: Into<String>>(mut self, format: S) -> Self {
        self.format = Some(format.into());
        self
    }

    /// The asset's IANA media type (`dc:format`), if present.
    pub fn format(&self) -> Option<&str> {
        self.format.as_deref()
    }

    pub fn add_type(mut self, at: AssetType) -> Self {
        self.types.push(at);
        self
    }

    pub fn types(&self) -> &Vec<AssetType> {
        &self.types
    }

    pub fn set_metadata(mut self, md: AssertionMetadata) -> Self {
        self.metadata = Some(md);
        self
    }

    pub fn metadata(&self) -> Option<&AssertionMetadata> {
        self.metadata.as_ref()
    }
}

impl AssertionCbor for AssetTypes {}

impl AssertionBase for AssetTypes {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_written_as_v2() {
        let assertion = AssetTypes::from_format("text/csv").to_assertion().unwrap();
        assert_eq!(assertion.label(), "c2pa.asset-type.v2");
    }

    #[test]
    fn test_format_and_types_round_trip() {
        let original = AssetTypes::new(AssetType::new(
            AssetTypeEnum::ModelTensorflow,
            Some("2.11.0".to_string()),
        ))
        .add_type(AssetType::new(AssetTypeEnum::TensorflowSaveModel, None))
        .set_format("application/octet-stream");

        let assertion = original.to_assertion().unwrap();
        let decoded = AssetTypes::from_assertion(&assertion).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.format(), Some("application/octet-stream"));
        assert_eq!(decoded.types()[0].asset_type, "c2pa.types.model.tensorflow");
    }

    #[test]
    fn test_omits_absent_fields() {
        // `types` and `metadata` are optional, and absent fields are left out rather than
        // written as empty or null.
        let assertion = AssetTypes::from_format("text/csv").to_assertion().unwrap();
        let map: std::collections::BTreeMap<String, c2pa_cbor::Value> =
            c2pa_cbor::from_slice(assertion.data()).unwrap();
        assert_eq!(map.keys().collect::<Vec<_>>(), ["dc:format"]);

        let decoded = AssetTypes::from_assertion(&assertion).unwrap();
        assert!(decoded.types().is_empty());
        assert!(decoded.metadata().is_none());
    }

    #[test]
    fn test_reads_v1() {
        // A deprecated `c2pa.asset-type` assertion, as earlier versions wrote it.
        let cbor = c2pa_cbor::to_vec(&c2pa_cbor::Value::Map(
            [
                (
                    c2pa_cbor::Value::Text("types".to_string()),
                    c2pa_cbor::Value::Array(vec![c2pa_cbor::Value::Map(
                        [(
                            c2pa_cbor::Value::Text("type".to_string()),
                            c2pa_cbor::Value::Text("c2pa.types.dataset".to_string()),
                        )]
                        .into_iter()
                        .collect(),
                    )]),
                ),
                (
                    c2pa_cbor::Value::Text("metadata".to_string()),
                    c2pa_cbor::Value::Null,
                ),
            ]
            .into_iter()
            .collect(),
        ))
        .unwrap();
        let assertion = Assertion::new(
            labels::ASSET_TYPE,
            None,
            crate::assertion::AssertionData::Cbor(cbor),
        );

        let decoded = AssetTypes::from_assertion(&assertion).unwrap();
        assert_eq!(decoded.types()[0].asset_type, "c2pa.types.dataset");
        assert_eq!(decoded.format(), None);
    }

    #[test]
    fn test_new_type_values() {
        for (value, label) in [
            (AssetTypeEnum::AuditLog, "c2pa.types.audit-log"),
            (
                AssetTypeEnum::ModelHuggingFaceTransformers,
                "c2pa.types.model.huggingface.transformers",
            ),
            (AssetTypeEnum::ModelXgBoost, "c2pa.types.model.xgboost"),
            (AssetTypeEnum::VersionHistory, "c2pa.types.version-history"),
        ] {
            assert_eq!(String::from(value), label);
        }
    }
}
