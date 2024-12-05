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

use super::{labels, AssetType, Metadata};
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
            AssetTypeEnum::Other(v) => v,
        }
    }
}

const ASSERTION_CREATION_VERSION: usize = 1;

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct AssetTypes {
    types: Vec<AssetType>,
    metadata: Option<Metadata>,
}

#[allow(dead_code)]
impl AssetTypes {
    /// See <https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_asset_type>.
    pub const LABEL: &'static str = labels::ASSET_TYPE;

    pub fn new(at: AssetType) -> Self {
        AssetTypes {
            types: vec![at],
            metadata: None,
        }
    }

    pub fn add_type(mut self, at: AssetType) -> Self {
        self.types.push(at);
        self
    }

    pub fn types(&self) -> &Vec<AssetType> {
        &self.types
    }

    pub fn set_metadata(mut self, md: Metadata) -> Self {
        self.metadata = Some(md);
        self
    }

    pub fn metadata(&self) -> Option<&Metadata> {
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
