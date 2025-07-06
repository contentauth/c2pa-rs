const fs = require('fs');
const path = require('path');
const { C2paReader, version, name } = require('../pkg-node/c2pa_wasm');

console.log(`${name()} v${version()}`);
console.log('Supported MIME types:', C2paReader.supported_mime_types());

function readC2PAFromFile(filePath) {
    try {
        console.log(`\nReading C2PA data from: ${filePath}`);
        
        // Read file data
        const fileData = fs.readFileSync(filePath);
        console.log(`File size: ${fileData.length} bytes`);
        
        // Determine format from file extension
        const ext = path.extname(filePath).toLowerCase();
        let format;
        switch (ext) {
            case '.jpg':
            case '.jpeg':
                format = 'image/jpeg';
                break;
            case '.png':
                format = 'image/png';
                break;
            case '.tiff':
            case '.tif':
                format = 'image/tiff';
                break;
            case '.webp':
                format = 'image/webp';
                break;
            case '.avif':
                format = 'image/avif';
                break;
            case '.heic':
                format = 'image/heic';
                break;
            case '.heif':
                format = 'image/heif';
                break;
            case '.mp4':
                format = 'video/mp4';
                break;
            case '.m4a':
                format = 'audio/mp4';
                break;
            default:
                throw new Error(`Unsupported file extension: ${ext}`);
        }
        
        console.log(`Format: ${format}`);
        
        // Create reader
        const reader = new C2paReader(new Uint8Array(fileData), format);
        
        // Get basic information
        const validationState = reader.validation_state();
        const hasActiveManifest = reader.has_active_manifest();
        
        console.log(`\nValidation State: ${validationState}`);
        console.log(`Has Active Manifest: ${hasActiveManifest}`);
        
        if (hasActiveManifest) {
            const activeLabel = reader.active_label();
            const title = reader.get_title();
            const format = reader.get_format();
            const instanceId = reader.get_instance_id();
            
            console.log(`Active Label: ${activeLabel}`);
            console.log(`Title: ${title || 'None'}`);
            console.log(`Format: ${format || 'Unknown'}`);
            console.log(`Instance ID: ${instanceId || 'None'}`);
            
            // Get claim generator info
            const claimGenerator = reader.get_claim_generator();
            if (claimGenerator) {
                console.log('\nClaim Generator:');
                console.log(JSON.stringify(JSON.parse(claimGenerator), null, 2));
            }
            
            // Get ingredients
            const ingredients = reader.get_ingredients();
            if (ingredients) {
                const ingredientsList = JSON.parse(ingredients);
                console.log(`\nIngredients (${ingredientsList.length}):`);
                ingredientsList.forEach((ingredient, index) => {
                    console.log(`  ${index + 1}. ${ingredient.title || 'Untitled'} (${ingredient.format || 'Unknown format'})`);
                });
            }
            
            // Get assertions
            const assertions = reader.get_assertions();
            if (assertions) {
                const assertionsList = JSON.parse(assertions);
                console.log(`\nAssertions (${assertionsList.length}):`);
                assertionsList.forEach((assertion, index) => {
                    console.log(`  ${index + 1}. ${assertion.label} (${assertion.kind || 'Unknown kind'})`);
                });
            }
            
            // Get validation status
            const validationStatus = reader.validation_status();
            if (validationStatus) {
                const statusList = JSON.parse(validationStatus);
                if (statusList.length > 0) {
                    console.log(`\nValidation Issues (${statusList.length}):`);
                    statusList.forEach((status, index) => {
                        console.log(`  ${index + 1}. ${status.code}: ${status.explanation}`);
                    });
                }
            }
            
            // Get full manifest
            const manifest = reader.json();
            console.log('\nFull Manifest:');
            console.log(JSON.stringify(JSON.parse(manifest), null, 2));
        }
        
        return {
            validationState,
            hasActiveManifest,
            manifest: reader.json()
        };
        
    } catch (error) {
        console.error(`Error reading C2PA data: ${error.message}`);
        return null;
    }
}

// Example usage
if (process.argv.length < 3) {
    console.log('Usage: node index.js <path-to-c2pa-file>');
    console.log('Example: node index.js ../../../sdk/tests/fixtures/C.jpg');
    process.exit(1);
}

const filePath = process.argv[2];
if (!fs.existsSync(filePath)) {
    console.error(`File not found: ${filePath}`);
    process.exit(1);
}

readC2PAFromFile(filePath);
