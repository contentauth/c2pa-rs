# C2PA Rust SDK Architecture Overview

This document provides a comprehensive overview of the core SDK architecture in the `c2pa-rs` project. The SDK implements the [C2PA technical specification](https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html) and enables applications to create, sign, embed, and validate C2PA manifests in various asset types.

## Table of Contents

- [Overview](#overview)
- [Core Architecture](#core-architecture)
- [Major Components](#major-components)
  - [Public API Layer](#public-api-layer)
  - [Manifest Store & Claims](#manifest-store--claims)
  - [Assertions](#assertions)
  - [Ingredients](#ingredients)
  - [Cryptography & Signing](#cryptography--signing)
  - [Asset Handlers](#asset-handlers)
  - [JUMBF Structure](#jumbf-structure)
  - [Identity & Validation](#identity--validation)
  - [Resource Management](#resource-management)
- [Data Flow](#data-flow)
- [Key Design Patterns](#key-design-patterns)

## Overview

The C2PA Rust SDK provides a comprehensive implementation for working with Content Credentials (C2PA manifests). It supports:

- **Reading**: Parse and validate C2PA manifests from signed assets
- **Writing**: Create and sign new C2PA manifests
- **Validation**: Verify cryptographic signatures and trust chains
- **Multiple formats**: JPEG, PNG, TIFF, GIF, MP3, MP4, PDF, SVG, and more
- **Identity assertions**: Support for CAWG identity specifications
- **Async/sync APIs**: Full support for both synchronous and asynchronous operations

## Core Architecture

The SDK follows a layered architecture design:

```mermaid
graph TB
    subgraph "Public API Layer"
        Reader["Reader<br/>(Read & Validate)"]
        Builder["Builder<br/>(Create & Sign)"]
    end
    
    subgraph "Core Layer"
        Manifest["Manifest"]
        Store["Store<br/>(Manifest Store)"]
        Claim["Claim"]
        Ingredient["Ingredient"]
    end
    
    subgraph "Assertion Layer"
        Actions["Actions"]
        Metadata["Metadata"]
        Thumbnail["Thumbnail"]
        Identity["Identity"]
        CustomAssertions["Custom Assertions"]
    end
    
    subgraph "Cryptography Layer"
        Signer["Signer/AsyncSigner"]
        COSE["COSE Signing"]
        Validator["COSE Validator"]
        TimeStamp["Time Stamp"]
        OCSP["OCSP"]
    end
    
    subgraph "I/O Layer"
        AssetHandlers["Asset Handlers"]
        JUMBF["JUMBF I/O"]
        ResourceStore["Resource Store"]
    end
    
    Reader --> Store
    Builder --> Store
    Store --> Claim
    Store --> Manifest
    Manifest --> Ingredient
    Manifest --> Actions
    Manifest --> Metadata
    Manifest --> Thumbnail
    Manifest --> Identity
    Manifest --> CustomAssertions
    Builder --> Signer
    Store --> Validator
    Signer --> COSE
    Validator --> COSE
    COSE --> TimeStamp
    COSE --> OCSP
    Store --> JUMBF
    JUMBF --> AssetHandlers
    Manifest --> ResourceStore
```

## Major Components

### Public API Layer

The SDK provides two primary entry points for users:

#### Builder

The **Builder** is used to create and sign C2PA manifests. It provides a fluent API for:
- Defining manifest structure via JSON or programmatic API
- Adding assertions (standard and custom)
- Adding ingredients from existing assets
- Signing manifests with various cryptographic algorithms
- Embedding manifests into assets

```mermaid
graph LR
    subgraph "Builder API"
        BuilderNew["Builder::new()"]
        AddAssertion["add_assertion()"]
        AddIngredient["add_ingredient()"]
        Sign["sign_file() / sign_stream()"]
    end
    
    ManifestDef["ManifestDefinition<br/>(JSON/Struct)"]
    Assertions["Assertions"]
    Ingredients["Ingredients"]
    SignedAsset["Signed Asset<br/>with embedded manifest"]
    
    ManifestDef --> BuilderNew
    BuilderNew --> AddAssertion
    AddAssertion --> Assertions
    AddIngredient --> Ingredients
    AddAssertion --> Sign
    AddIngredient --> Sign
    Sign --> SignedAsset
```

**Key files:**
- `sdk/src/builder.rs` - Main builder implementation
- `sdk/src/lib.rs` - Public exports

#### Reader

The **Reader** validates and extracts C2PA manifests from assets:
- Reads manifests from file streams
- Validates cryptographic signatures
- Checks trust chains
- Provides validation reports
- Extracts manifest data as JSON or structured objects

```mermaid
graph LR
    subgraph "Reader API"
        FromStream["Reader::from_stream()"]
        ActiveManifest["active_manifest()"]
        GetAssertion["find_assertion()"]
        Validate["validation_status()"]
    end
    
    Asset["Signed Asset"]
    ManifestData["Manifest Data"]
    ValidationResults["ValidationResults"]
    
    Asset --> FromStream
    FromStream --> ActiveManifest
    ActiveManifest --> GetAssertion
    FromStream --> Validate
    GetAssertion --> ManifestData
    Validate --> ValidationResults
```

**Key files:**
- `sdk/src/reader.rs` - Main reader implementation
- `sdk/src/validation_results.rs` - Validation reporting

### Manifest Store & Claims

The **Store** is the central internal component managing the collection of manifests in an asset.

```mermaid
graph TB
    subgraph "Manifest Store"
        Store["Store"]
        ActiveManifest["Active Manifest<br/>(Most recent)"]
        PreviousManifests["Previous Manifests<br/>(History chain)"]
    end
    
    subgraph "Claim Structure"
        Claim["Claim<br/>(Core data structure)"]
        ClaimData["Claim Assertions"]
        ClaimSig["Claim Signature"]
        ClaimIngredients["Referenced Ingredients"]
    end
    
    subgraph "Manifest Structure"
        Manifest["Manifest<br/>(User-facing)"]
        ManifestAssertions["Assertions"]
        ManifestIngredients["Ingredients"]
        ManifestMetadata["Metadata"]
        SignatureInfo["Signature Info"]
    end
    
    Store --> ActiveManifest
    Store --> PreviousManifests
    ActiveManifest --> Manifest
    PreviousManifests --> Manifest
    Manifest --> Claim
    Claim --> ClaimData
    Claim --> ClaimSig
    Claim --> ClaimIngredients
    Manifest --> ManifestAssertions
    Manifest --> ManifestIngredients
    Manifest --> ManifestMetadata
    Manifest --> SignatureInfo
```

**Key concepts:**
- **Store**: Container for all manifests in an asset (active + historical)
- **Claim**: Internal representation of signed data (JUMBF structure)
- **Manifest**: User-facing representation of claim data
- **Provenance chain**: Linked history of all edits/modifications

**Key files:**
- `sdk/src/store.rs` - Manifest store implementation (~8500 lines)
- `sdk/src/claim.rs` - Claim structure and operations (~4000 lines)
- `sdk/src/manifest.rs` - Manifest API (~1900 lines)

### Assertions

Assertions are pieces of metadata that describe the asset. The SDK supports both standard C2PA assertions and custom assertions.

```mermaid
graph TB
    subgraph "Standard C2PA Assertions"
        Actions["Actions<br/>(c2pa.actions)"]
        CreativeWork["Creative Work<br/>(stds.schema-org.CreativeWork)"]
        DataHash["Data Hash<br/>(c2pa.hash.data)"]
        Thumbnail["Thumbnail<br/>(c2pa.thumbnail)"]
        BmffHash["BMFF Hash<br/>(c2pa.hash.bmff)"]
        BoxHash["Box Hash<br/>(c2pa.hash.boxes)"]
    end
    
    subgraph "Metadata Assertions"
        EXIF["EXIF<br/>(stds.exif)"]
        Metadata["Asset Metadata<br/>(c2pa.assertions.metadata)"]
        SchemaOrg["Schema.org<br/>(schema.org)"]
    end
    
    subgraph "Advanced Assertions"
        Identity["Identity<br/>(cawg.identity)"]
        SoftBinding["Soft Binding<br/>(c2pa.soft-binding)"]
        EmbeddedData["Embedded Data"]
    end
    
    subgraph "Custom Assertions"
        UserCBOR["User CBOR<br/>(custom labels)"]
        UserJSON["User JSON<br/>(custom labels)"]
    end
    
    AssertionBase["Assertion Base Trait"]
    
    Actions --> AssertionBase
    CreativeWork --> AssertionBase
    DataHash --> AssertionBase
    Thumbnail --> AssertionBase
    BmffHash --> AssertionBase
    BoxHash --> AssertionBase
    EXIF --> AssertionBase
    Metadata --> AssertionBase
    SchemaOrg --> AssertionBase
    Identity --> AssertionBase
    SoftBinding --> AssertionBase
    EmbeddedData --> AssertionBase
    UserCBOR --> AssertionBase
    UserJSON --> AssertionBase
```

**Key assertion types:**

1. **Actions** (`c2pa.actions`): Documents what was done to the asset
   - Examples: edited, cropped, filtered, color_adjusted
   - Includes parameters and software information

2. **Hashes** (`c2pa.hash.*`): Cryptographic hashes for validation
   - Data hash: Hash of the asset binary data
   - BMFF hash: Hash for video containers (MP4, etc.)
   - Box hash: Hash of specific boxes/chunks

3. **Metadata** (`c2pa.assertions.metadata`): Human and machine-readable metadata
   - Title, description, author
   - Location, creation date
   - Rights and licensing

4. **Thumbnail** (`c2pa.thumbnail`): Visual representation of asset state

5. **Identity** (`cawg.identity`): CAWG identity assertion for advanced identity verification

**Key files:**
- `sdk/src/assertions/` - All assertion implementations (23 files)
- `sdk/src/assertion.rs` - Base assertion trait and logic

### Ingredients

Ingredients represent external assets used in creating the current asset. They preserve provenance chains.

```mermaid
graph TB
    subgraph "Ingredient Structure"
        Ingredient["Ingredient"]
        IngTitle["Title"]
        IngFormat["Format (MIME)"]
        IngThumbnail["Thumbnail"]
        IngHash["Hash"]
        IngRelationship["Relationship"]
        IngManifest["Embedded Manifest<br/>(if C2PA signed)"]
        IngValidation["Validation Results"]
    end
    
    subgraph "Relationship Types"
        ParentOf["parentOf<br/>(Primary source)"]
        ComponentOf["componentOf<br/>(Merged element)"]
        InputTo["inputTo<br/>(Processing input)"]
    end
    
    Ingredient --> IngTitle
    Ingredient --> IngFormat
    Ingredient --> IngThumbnail
    Ingredient --> IngHash
    Ingredient --> IngRelationship
    Ingredient --> IngManifest
    Ingredient --> IngValidation
    
    IngRelationship --> ParentOf
    IngRelationship --> ComponentOf
    IngRelationship --> InputTo
```

**Key features:**
- Preserves full C2PA manifests from source assets
- Maintains provenance chain across multiple edits
- Supports various relationship types (parent, component, input)
- Automatic thumbnail extraction when available
- Validation of ingredient manifests

**Key files:**
- `sdk/src/ingredient.rs` - Ingredient implementation (~2100 lines)

### Cryptography & Signing

The cryptography layer handles all signing and validation operations.

```mermaid
graph TB
    subgraph "Signing Interface"
        Signer["Signer Trait"]
        AsyncSigner["AsyncSigner Trait"]
        CallbackSigner["CallbackSigner"]
    end
    
    subgraph "Signing Implementations"
        CreateSigner["create_signer module"]
        OpenSSLSigner["OpenSSL Signers"]
        RustNativeSigner["Rust Native Signers"]
    end
    
    subgraph "Algorithms"
        PS256["PS256 (RSA-PSS)"]
        PS384["PS384 (RSA-PSS)"]
        PS512["PS512 (RSA-PSS)"]
        ES256["ES256 (ECDSA P-256)"]
        ES384["ES384 (ECDSA P-384)"]
        ES512["ES512 (ECDSA P-521)"]
        ED25519["ED25519"]
    end
    
    subgraph "COSE Layer"
        COSESign["cose_sign()<br/>cose_sign_async()"]
        COSEVerify["verify_cose()<br/>verify_cose_async()"]
    end
    
    subgraph "Supporting Services"
        TimeStamp["Time Stamp Authority<br/>(RFC 3161)"]
        OCSP["OCSP<br/>(Revocation Check)"]
        TrustPolicy["Certificate Trust Policy"]
    end
    
    Signer --> CreateSigner
    AsyncSigner --> CreateSigner
    CreateSigner --> OpenSSLSigner
    CreateSigner --> RustNativeSigner
    
    OpenSSLSigner --> PS256
    OpenSSLSigner --> PS384
    OpenSSLSigner --> PS512
    OpenSSLSigner --> ES256
    OpenSSLSigner --> ES384
    OpenSSLSigner --> ES512
    OpenSSLSigner --> ED25519
    
    RustNativeSigner --> PS256
    RustNativeSigner --> ES256
    RustNativeSigner --> ED25519
    
    Signer --> COSESign
    COSESign --> TimeStamp
    COSESign --> OCSP
    COSEVerify --> TrustPolicy
    COSEVerify --> OCSP
```

**Key components:**

1. **Signer trait**: Interface for cryptographic signing
   - Supports sync and async variants
   - Pluggable signature implementations
   - Built-in support for time stamping and OCSP

2. **COSE (CBOR Object Signing and Encryption)**: C2PA's signature format
   - Standard defined in RFC 8152
   - Supports multiple algorithms
   - Includes certificate chains

3. **Time Stamping**: RFC 3161 trusted time stamps
   - Proves when signing occurred
   - Protects against backdating

4. **OCSP (Online Certificate Status Protocol)**: Certificate revocation checking
   - Real-time validation of certificate status
   - Can be embedded in signature

5. **Trust policies**: Configurable trust validation
   - Custom trust anchors
   - Certificate chain validation
   - Extended Key Usage (EKU) verification

**Key files:**
- `sdk/src/signer.rs` - Signer traits
- `sdk/src/create_signer.rs` - Signer factory functions
- `sdk/src/cose_sign.rs` - COSE signing implementation
- `sdk/src/cose_validator.rs` - COSE validation
- `sdk/src/crypto/` - Cryptography primitives (66 files)
  - `sdk/src/crypto/cose/` - COSE implementation
  - `sdk/src/crypto/raw_signature/` - Signing algorithms
  - `sdk/src/crypto/time_stamp/` - Time stamping
  - `sdk/src/crypto/ocsp/` - OCSP support

### Asset Handlers

Asset handlers provide format-specific I/O operations for different file types.

```mermaid
graph LR
    subgraph "Asset Handler Interface"
        AssetIO["AssetIO Trait"]
        CAIRead["CAIRead Trait<br/>(Read + Seek)"]
        CAIReadWrite["CAIReadWrite Trait<br/>(Read + Seek + Write)"]
    end
    
    subgraph "Image Handlers"
        JPEG["JPEG Handler<br/>(jpeg_io)"]
        PNG["PNG Handler<br/>(png_io)"]
        TIFF["TIFF Handler<br/>(tiff_io)"]
        GIF["GIF Handler<br/>(gif_io)"]
        SVG["SVG Handler<br/>(svg_io)"]
    end
    
    subgraph "Video/Audio Handlers"
        BMFF["BMFF Handler<br/>(MP4/MOV)<br/>(bmff_io)"]
        RIFF["RIFF Handler<br/>(WAV/WebP)<br/>(riff_io)"]
        MP3["MP3 Handler<br/>(mp3_io)"]
    end
    
    subgraph "Document Handlers"
        PDF["PDF Handler<br/>(pdf_io)"]
        C2PA["C2PA Handler<br/>(.c2pa files)<br/>(c2pa_io)"]
    end
    
    AssetIO --> CAIRead
    AssetIO --> CAIReadWrite
    
    JPEG -.implements.-> AssetIO
    PNG -.implements.-> AssetIO
    TIFF -.implements.-> AssetIO
    GIF -.implements.-> AssetIO
    SVG -.implements.-> AssetIO
    BMFF -.implements.-> AssetIO
    RIFF -.implements.-> AssetIO
    MP3 -.implements.-> AssetIO
    PDF -.implements.-> AssetIO
    C2PA -.implements.-> AssetIO
```

**Handler responsibilities:**
- Locate C2PA data within format-specific structures
- Extract C2PA manifests from assets
- Embed C2PA manifests into assets
- Handle format-specific quirks and constraints
- Preserve existing metadata when possible

**Key operations:**
- `read_cai()`: Extract C2PA manifest store
- `save_cai_store()`: Embed manifest store
- `remote_ref_writer_ref()`: Handle external manifests
- `supported_types()`: Report MIME types supported

**Key files:**
- `sdk/src/asset_handlers/` - All format handlers (12 files)
- `sdk/src/asset_io.rs` - Common I/O traits

### JUMBF Structure

JUMBF (JPEG Universal Metadata Box Format) is the container format for C2PA data. It's based on ISO BMFF (Base Media File Format).

```mermaid
graph TB
    subgraph "JUMBF Hierarchy"
        C2PA["C2PA Manifest Store<br/>(Top-level JUMBF box)"]
        
        subgraph "Per Manifest"
            Manifest["Manifest<br/>(JUMBF superbox)"]
            Claim["Claim<br/>(c2pa.claim)"]
            Assertions["Assertions<br/>(c2pa.assertions)"]
            Signature["Signature<br/>(c2pa.signature)"]
            Credentials["Credentials<br/>(c2pa.credentials)"]
        end
        
        subgraph "Assertion Boxes"
            AssertionCBOR["CBOR Assertion"]
            AssertionJSON["JSON Assertion"]
            AssertionUUID["UUID Assertion"]
        end
        
        subgraph "Data Boxes"
            DataBoxes["Data Boxes<br/>(c2pa.databoxes)"]
            DataBoxCBOR["CBOR Content"]
            DataBoxBinary["Binary Content"]
        end
    end
    
    C2PA --> Manifest
    Manifest --> Claim
    Manifest --> Assertions
    Manifest --> Signature
    Manifest --> Credentials
    Manifest --> DataBoxes
    
    Assertions --> AssertionCBOR
    Assertions --> AssertionJSON
    Assertions --> AssertionUUID
    
    DataBoxes --> DataBoxCBOR
    DataBoxes --> DataBoxBinary
```

**JUMBF box types:**
- **Superbox**: Container for other boxes (like a directory)
- **CBOR box**: Contains CBOR-encoded data
- **JSON box**: Contains JSON-encoded data
- **UUID box**: Contains binary data identified by UUID
- **Embedded file**: Contains embedded binary assets

**Label structure:**
- Uses URN-style identifiers: `urn:c2pa:manifest:label`
- Hierarchical organization: `manifest/assertion/sub-assertion`
- Standard labels defined by C2PA specification
- Custom labels use reverse-domain notation

**Key files:**
- `sdk/src/jumbf/` - JUMBF implementation (4 files)
  - `boxes.rs` - Box structure definitions
  - `boxio.rs` - Box I/O operations
  - `labels.rs` - Label utilities
- `sdk/src/jumbf_io.rs` - High-level JUMBF I/O

### Identity & Validation

The identity module implements the CAWG (Coalition for Authenticity and Governance) identity assertion specification.

```mermaid
graph TB
    subgraph "Identity Assertion"
        ICA["Identity Assertion<br/>(cawg.identity)"]
        SignerPayload["Signer Payload"]
        Credentials["Credentials<br/>(W3C VC or X.509)"]
    end
    
    subgraph "Credential Types"
        W3CVC["W3C Verifiable Credentials"]
        X509["X.509 Certificates"]
        BuiltIn["Built-in Credentials"]
    end
    
    subgraph "Verification"
        SignatureVerifier["Signature Verifier"]
        X509Verifier["X509 Signature Verifier"]
        BuiltInVerifier["Built-in Signature Verifier"]
        CustomVerifier["Custom Verifiers"]
    end
    
    subgraph "W3C VC Support"
        DID["DID Resolution<br/>(did:web, etc.)"]
        DIDDoc["DID Document"]
        JWK["JSON Web Keys"]
        VCValidation["VC Validation"]
    end
    
    subgraph "Validation Results"
        ValidationError["Validation Error"]
        CredentialSummary["Credential Summary"]
        ValidationReport["Validation Report"]
    end
    
    ICA --> SignerPayload
    ICA --> Credentials
    
    Credentials --> W3CVC
    Credentials --> X509
    Credentials --> BuiltIn
    
    ICA --> SignatureVerifier
    SignatureVerifier --> X509Verifier
    SignatureVerifier --> BuiltInVerifier
    SignatureVerifier --> CustomVerifier
    
    W3CVC --> DID
    DID --> DIDDoc
    DIDDoc --> JWK
    W3CVC --> VCValidation
    
    SignatureVerifier --> ValidationError
    SignatureVerifier --> CredentialSummary
    SignatureVerifier --> ValidationReport
```

**Key features:**

1. **Identity Assertion Builder**: Create identity assertions with credentials
2. **Multiple credential types**: X.509 certificates, W3C Verifiable Credentials, built-in credentials
3. **DID support**: Resolution of Decentralized Identifiers (DID)
4. **Signature verification**: Pluggable verification system
5. **Claim aggregation**: Support for multi-credential validation

**Validation states:**
- **Invalid**: Fails structural or cryptographic requirements
- **Valid**: Well-formed and cryptographically sound
- **Trusted**: Valid and signed by trusted authority

**Key files:**
- `sdk/src/identity/` - Identity implementation (80 files)
  - `builder/` - Identity assertion creation
  - `identity_assertion/` - Core assertion structure
  - `x509/` - X.509 credential support
  - `claim_aggregation/` - W3C VC support
  - `validator.rs` - Validation logic

### Resource Management

The resource store manages binary resources (thumbnails, embedded data, etc.) referenced by manifests.

```mermaid
graph LR
    subgraph "Resource Store"
        Store["ResourceStore"]
        Resources["HashMap<identifier, data>"]
        Resolver["ResourceResolver"]
    end
    
    subgraph "Resource References"
        ResourceRef["ResourceRef<br/>(identifier + format)"]
        HashedUri["HashedUri<br/>(URI + hash)"]
        UriOrResource["UriOrResource<br/>(enum)"]
    end
    
    subgraph "Resource Types"
        Thumbnails["Thumbnails<br/>(JPEG, PNG)"]
        EmbeddedFiles["Embedded Files"]
        Icons["Icons"]
        CustomData["Custom Binary Data"]
    end
    
    Store --> Resources
    Store --> Resolver
    
    ResourceRef --> Store
    HashedUri --> Store
    UriOrResource --> ResourceRef
    UriOrResource --> HashedUri
    
    Store --> Thumbnails
    Store --> EmbeddedFiles
    Store --> Icons
    Store --> CustomData
```

**Key concepts:**
- **ResourceRef**: Local reference before signing (identifier-based)
- **HashedUri**: Final reference after signing (URI + hash)
- **UriOrResource**: Union type that can be either
- **ResourceResolver**: Custom resolution logic for external resources

**Key files:**
- `sdk/src/resource_store.rs` - Resource management (~500 lines)

## Data Flow

### Creating a Signed Manifest

```mermaid
sequenceDiagram
    participant App
    participant Builder
    participant Store
    participant Claim
    participant Signer
    participant AssetHandler
    
    App->>Builder: Create from ManifestDefinition
    App->>Builder: Add assertions
    App->>Builder: Add ingredients
    App->>Builder: sign_file(signer, input, output)
    
    Builder->>Store: Create Store with claims
    Store->>Claim: Build Claim structure
    Claim->>Claim: Add assertions to JUMBF
    Claim->>Claim: Add ingredient references
    
    Builder->>Signer: Sign claim data
    Signer->>Signer: Generate signature (COSE)
    Signer-->>Builder: Return signature
    
    Builder->>Store: Add signature to store
    Store->>AssetHandler: Write JUMBF to asset
    AssetHandler-->>Builder: Signed asset created
    Builder-->>App: Success
```

### Reading and Validating a Manifest

```mermaid
sequenceDiagram
    participant App
    participant Reader
    participant Store
    participant AssetHandler
    participant Validator
    participant Claim
    
    App->>Reader: from_stream(format, stream)
    Reader->>AssetHandler: Detect format
    AssetHandler->>AssetHandler: Extract JUMBF data
    AssetHandler-->>Reader: JUMBF bytes
    
    Reader->>Store: Load from JUMBF
    Store->>Claim: Parse each manifest
    Claim->>Claim: Parse assertions
    
    Reader->>Validator: Validate signatures
    Validator->>Validator: Verify COSE signatures
    Validator->>Validator: Check certificate chains
    Validator->>Validator: Validate time stamps
    Validator->>Validator: Check OCSP status
    Validator-->>Reader: ValidationResults
    
    Reader->>Store: Generate Manifests
    Store-->>Reader: Active + historical manifests
    Reader-->>App: Reader with manifests
```

### Ingredient Processing

```mermaid
sequenceDiagram
    participant Builder
    participant Ingredient
    participant Store
    participant Reader
    participant ResourceStore
    
    Builder->>Ingredient: Create from file/stream
    Ingredient->>Reader: Read source asset
    Reader->>Store: Extract existing manifests
    Store-->>Reader: Manifest data
    Reader-->>Ingredient: Embedded manifest
    
    Ingredient->>Ingredient: Extract thumbnail
    Ingredient->>Ingredient: Calculate hash
    Ingredient->>ResourceStore: Store thumbnail
    
    Ingredient-->>Builder: Ingredient with provenance
    Builder->>Builder: Add to manifest
```

## Key Design Patterns

### 1. Async/Sync Duality

The SDK supports both synchronous and asynchronous operations through the `async_generic` macro:

```rust
#[async_generic]
pub fn from_stream(format: &str, stream: impl Read + Seek) -> Result<Reader> {
    // Implementation works for both sync and async
}
```

This generates both `from_stream()` and `from_stream_async()` from a single implementation.

### 2. Trait-Based Extensibility

Key extension points use traits:
- **Signer/AsyncSigner**: Custom signing implementations
- **AssetIO**: New file format support
- **AssertionBase**: Custom assertion types
- **PostValidator**: Custom validation logic

### 3. Stream-Based Processing

The SDK emphasizes stream-based I/O:
- Reduces memory footprint
- Supports large files
- Enables progressive processing
- Works with any `Read + Seek` source

### 4. Builder Pattern

The Builder API uses the builder pattern extensively:
- Fluent method chaining
- Progressive construction
- Validation before signing
- Clear separation of concerns

### 5. Error Handling

Comprehensive error handling using Result types:
- Rich error types with context
- Error propagation with `?` operator
- Validation errors vs. structural errors
- Detailed error messages

### 6. Feature Flags

Conditional compilation for different use cases:
- `openssl` vs `rust_native_crypto`
- `file_io` for filesystem operations
- `json_schema` for schema generation
- `pdf` for PDF support
- `fetch_remote_manifests` for network operations

### 7. Resource Management

Explicit resource management:
- ResourceStore for binary assets
- Automatic cleanup of temporary files
- Stream closing and error recovery
- Memory-efficient data structures

## Conclusion

The C2PA Rust SDK is a comprehensive, production-ready implementation of the C2PA specification. Its layered architecture provides:

- **Flexibility**: Support for multiple formats, algorithms, and use cases
- **Extensibility**: Trait-based design for custom implementations
- **Performance**: Stream-based processing and efficient data structures
- **Reliability**: Comprehensive validation and error handling
- **Standards compliance**: Full implementation of C2PA and CAWG specifications

The SDK is suitable for a wide range of applications, from command-line tools to server applications to embedded systems, with support for both synchronous and asynchronous execution models.

