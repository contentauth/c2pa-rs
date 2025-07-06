import { C2paReader, read_from_file, version, name } from '../pkg/c2pa_wasm';

// TypeScript example for using C2PA WASM bindings

interface C2PAResult {
  manifest: any;
  validationState: string;
  title?: string;
  format?: string;
  ingredients?: any[];
  assertions?: any[];
}

async function readC2PAFromFile(file: File): Promise<C2PAResult> {
  try {
    // Read C2PA data from the file
    const reader = await read_from_file(file);
    
    // Get the manifest as JSON
    const manifest = JSON.parse(reader.json());
    
    // Get validation information
    const validationState = reader.validation_state();
    
    // Get metadata
    const title = reader.get_title() || undefined;
    const format = reader.get_format() || undefined;
    const ingredients = reader.get_ingredients() ? JSON.parse(reader.get_ingredients()!) : undefined;
    const assertions = reader.get_assertions() ? JSON.parse(reader.get_assertions()!) : undefined;
    
    return {
      manifest,
      validationState,
      title,
      format,
      ingredients,
      assertions
    };
  } catch (error) {
    throw new Error(`Failed to read C2PA data: ${error}`);
  }
}

async function readC2PAFromBuffer(data: Uint8Array, format: string): Promise<C2PAResult> {
  try {
    // Create a reader from the buffer data
    const reader = new C2paReader(data, format);
    
    // Get the manifest as JSON
    const manifest = JSON.parse(reader.json());
    
    // Get validation information
    const validationState = reader.validation_state();
    
    // Get metadata
    const title = reader.get_title() || undefined;
    const fileFormat = reader.get_format() || undefined;
    const ingredients = reader.get_ingredients() ? JSON.parse(reader.get_ingredients()!) : undefined;
    const assertions = reader.get_assertions() ? JSON.parse(reader.get_assertions()!) : undefined;
    
    return {
      manifest,
      validationState,
      title,
      format: fileFormat,
      ingredients,
      assertions
    };
  } catch (error) {
    throw new Error(`Failed to read C2PA data: ${error}`);
  }
}

// Example usage for file input
export async function handleFileInput(fileInput: HTMLInputElement): Promise<void> {
  if (!fileInput.files || fileInput.files.length === 0) {
    console.log('No file selected');
    return;
  }

  const file = fileInput.files[0];
  
  try {
    console.log(`Reading C2PA data from: ${file.name}`);
    console.log(`Using C2PA SDK: ${name()} v${version()}`);
    
    const result = await readC2PAFromFile(file);
    
    console.log('Validation State:', result.validationState);
    console.log('Title:', result.title);
    console.log('Format:', result.format);
    console.log('Number of ingredients:', result.ingredients?.length || 0);
    console.log('Number of assertions:', result.assertions?.length || 0);
    console.log('Full manifest:', result.manifest);
    
  } catch (error) {
    console.error('Error reading C2PA data:', error);
  }
}

// Example usage for drag and drop
export async function handleFileDrop(event: DragEvent): Promise<void> {
  event.preventDefault();
  
  if (!event.dataTransfer?.files || event.dataTransfer.files.length === 0) {
    return;
  }
  
  const file = event.dataTransfer.files[0];
  
  try {
    const result = await readC2PAFromFile(file);
    displayResult(result, file.name);
  } catch (error) {
    displayError(`Error processing ${file.name}: ${error}`);
  }
}

function displayResult(result: C2PAResult, fileName: string): void {
  const outputElement = document.getElementById('output');
  if (!outputElement) return;
  
  const validationClass = result.validationState === 'valid' ? 'success' : 
                         result.validationState === 'invalid' ? 'error' : 'warning';
  
  outputElement.innerHTML = `
    <div class="result ${validationClass}">
      <h3>File: ${fileName}</h3>
      <p>Validation State: <span class="validation-state ${result.validationState}">${result.validationState}</span></p>
      ${result.title ? `<p>Title: ${result.title}</p>` : ''}
      ${result.format ? `<p>Format: ${result.format}</p>` : ''}
      ${result.ingredients ? `<p>Ingredients: ${result.ingredients.length}</p>` : ''}
      ${result.assertions ? `<p>Assertions: ${result.assertions.length}</p>` : ''}
      <details>
        <summary>Full Manifest (click to expand)</summary>
        <pre>${JSON.stringify(result.manifest, null, 2)}</pre>
      </details>
    </div>
  `;
}

function displayError(message: string): void {
  const outputElement = document.getElementById('output');
  if (!outputElement) return;
  
  outputElement.innerHTML = `
    <div class="result error">
      <h3>Error</h3>
      <p>${message}</p>
    </div>
  `;
}

// Export the main functions for use in other modules
export { readC2PAFromFile, readC2PAFromBuffer, C2paReader, version, name };
