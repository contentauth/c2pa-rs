# C2PA WASM Bindings

This package provides WebAssembly bindings for the C2PA (Coalition for Content Provenance and Authenticity) SDK, allowing you to read and validate C2PA manifests directly in web browsers and Node.js environments.

## Features

- 🔍 **Read C2PA manifests** from various file formats (JPEG, PNG, MP4, etc.)
- ✅ **Validate C2PA signatures** and manifests  
- 📄 **Extract metadata**, ingredients, and assertions
- 🌐 **Web and Node.js support** with TypeScript definitions
- 🚀 **High performance** with native Rust implementation
- 📦 **Multiple build targets** (web, Node.js, bundlers)

## Quick Start

### Installation

```bash
# Using the build script
cd c2pa-wasm
./build.sh

# Or manually with wasm-pack
wasm-pack build --target web --out-dir pkg
```

### Web Browser Example

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>C2PA Reader</title>
</head>
<body>
    <input type="file" id="file-input" accept="image/*">
    <div id="output"></div>

    <script type="module">
        import init, { C2paReader, read_from_file } from './pkg/c2pa_wasm.js';

        async function main() {
            await init(); // Initialize WASM module
            
            document.getElementById('file-input').addEventListener('change', async (e) => {
                const file = e.target.files[0];
                if (!file) return;

                try {
                    const reader = await read_from_file(file);
                    const manifest = JSON.parse(reader.json());
                    const validationState = reader.validation_state();
                    
                    console.log('Validation:', validationState);
                    console.log('Manifest:', manifest);
                } catch (error) {
                    console.error('No C2PA data found:', error.message);
                }
            });
        }
        
        main();
    </script>
</body>
</html>
```

### Node.js Example

```javascript
const fs = require('fs');
const { C2paReader } = require('./pkg-node/c2pa_wasm');

function readC2PA(filePath) {
    const data = fs.readFileSync(filePath);
    const reader = new C2paReader(new Uint8Array(data), 'image/jpeg');
    
    return {
        manifest: JSON.parse(reader.json()),
        validationState: reader.validation_state(),
        title: reader.get_title(),
        hasActiveManifest: reader.has_active_manifest()
    };
}

// Usage
const result = readC2PA('path/to/image.jpg');
console.log('C2PA Data:', result);
```

### TypeScript Example

```typescript
import { C2paReader, read_from_file } from './pkg/c2pa_wasm';

async function processFile(file: File) {
    const reader = await read_from_file(file);
    
    return {
        manifest: JSON.parse(reader.json()),
        validationState: reader.validation_state(),
        title: reader.get_title(),
        ingredients: reader.get_ingredients() ? JSON.parse(reader.get_ingredients()!) : null,
        assertions: reader.get_assertions() ? JSON.parse(reader.get_assertions()!) : null
    };
}
```

## Building

To build the WASM package, you'll need to have `wasm-pack` installed:

```bash
# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Build the package
wasm-pack build --target web --out-dir pkg
```

### Build Targets

- `--target web` - For use in web browsers with ES modules
- `--target nodejs` - For use in Node.js environments  
- `--target bundler` - For use with bundlers like Webpack

## Usage

### Web Browser

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>C2PA WASM Example</title>
</head>
<body>
    <input type="file" id="file-input" accept="image/*">
    <div id="output"></div>

    <script type="module">
        import init, { C2paReader, read_from_file } from './pkg/c2pa_wasm.js';

        async function run() {
            // Initialize the WASM module
            await init();

            const fileInput = document.getElementById('file-input');
            const output = document.getElementById('output');

            fileInput.addEventListener('change', async (event) => {
                const file = event.target.files[0];
                if (!file) return;

                try {
                    // Read C2PA data from the file
                    const reader = await read_from_file(file);
                    
                    // Get the manifest as JSON
                    const manifest = reader.json();
                    
                    // Display validation status
                    const validationState = reader.validation_state();
                    
                    output.innerHTML = `
                        <h3>Validation State: ${validationState}</h3>
                        <pre>${JSON.stringify(JSON.parse(manifest), null, 2)}</pre>
                    `;
                } catch (error) {
                    output.innerHTML = `<p>Error: ${error.message}</p>`;
                }
            });
        }

        run();
    </script>
</body>
</html>
```

### JavaScript/TypeScript

```javascript
import init, { C2paReader } from 'c2pa-wasm';

async function readC2PA(fileData, format) {
    // Initialize the WASM module
    await init();
    
    // Create a reader from the file data
    const reader = new C2paReader(new Uint8Array(fileData), format);
    
    // Get the manifest as JSON
    const manifest = reader.json();
    
    // Check validation state
    const validationState = reader.validation_state();
    
    // Get specific metadata
    const title = reader.get_title();
    const format = reader.get_format();
    const ingredients = reader.get_ingredients();
    
    return {
        manifest: JSON.parse(manifest),
        validationState,
        title,
        format,
        ingredients: ingredients ? JSON.parse(ingredients) : null
    };
}
```

### Node.js

```javascript
const fs = require('fs');
const { C2paReader } = require('./pkg/c2pa_wasm');

async function readC2PAFromFile(filePath) {
    const fileData = fs.readFileSync(filePath);
    const format = 'image/jpeg'; // or detect from file extension
    
    const reader = new C2paReader(new Uint8Array(fileData), format);
    
    return {
        manifest: JSON.parse(reader.json()),
        validationState: reader.validation_state(),
        title: reader.get_title(),
        ingredients: reader.get_ingredients()
    };
}
```

## API Reference

### `C2paReader`

Main class for reading C2PA manifests.

#### Constructor

- `new C2paReader(data: Uint8Array, format: string)` - Creates a reader from binary data and format

#### Methods

- `json(): string` - Get the manifest store as JSON
- `validation_state(): string` - Get validation state ("valid", "invalid", "trusted", "unknown")
- `validation_status(): string | null` - Get detailed validation status as JSON
- `active_label(): string | null` - Get the active manifest label
- `has_active_manifest(): boolean` - Check if there's an active manifest
- `get_title(): string | null` - Get the title of the active manifest
- `get_format(): string | null` - Get the format of the active manifest
- `get_instance_id(): string | null` - Get the instance ID
- `get_claim_generator(): string | null` - Get claim generator info as JSON
- `get_thumbnail_ref(): string | null` - Get thumbnail reference as JSON
- `get_ingredients(): string | null` - Get ingredients list as JSON
- `get_assertions(): string | null` - Get assertions list as JSON
- `get_signature_info(): string | null` - Get signature info as JSON

### Utility Functions

- `read_from_file(file: File): Promise<C2paReader>` - Create reader from File object
- `is_format_supported(format: string): boolean` - Check if format is supported
- `supported_mime_types(): string[]` - Get list of supported MIME types
- `version(): string` - Get SDK version
- `name(): string` - Get SDK name

## Testing

Run the test suite:

```bash
wasm-pack test --headless --chrome
```

## Supported Formats

The WASM bindings support the same file formats as the main C2PA SDK:

- JPEG/JPG
- PNG
- TIFF
- AVIF
- HEIF/HEIC
- WebP
- DNG
- MP4 (video)
- M4A (audio)
- And more...

Use `supported_mime_types()` to get the complete list.

## Error Handling

All methods that can fail will throw JavaScript errors. Make sure to wrap calls in try-catch blocks:

```javascript
try {
    const reader = new C2paReader(data, 'image/jpeg');
    const manifest = reader.json();
} catch (error) {
    console.error('Failed to read C2PA data:', error.message);
}
```

## Performance Notes

- The WASM module needs to be initialized once with `init()` before use
- Large files may take some time to process
- Consider using Web Workers for processing large files to avoid blocking the main thread

## License

This package is licensed under the same terms as the main C2PA SDK (MIT OR Apache-2.0).
