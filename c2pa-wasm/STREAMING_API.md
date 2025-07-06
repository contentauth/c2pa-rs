# C2PA WASM Streaming API

This document describes the new streaming API for c2pa-wasm that enables true async streaming support from JavaScript without loading entire assets into memory.

## Overview

The streaming API provides two main approaches:

1. **`C2paAsyncReader`** - A practical async reader that chunks data from JavaScript
2. **`C2paStreamReader`** - A lower-level streaming reader with JavaScript callbacks (requires sync callbacks)

## Current Implementation Status

⚠️ **Important Limitation**: The current implementation provides a bridge between async JavaScript and the sync C2PA SDK. This works but has limitations:

- JavaScript callbacks must be synchronous or return pre-resolved promises
- True async streaming requires future C2PA SDK refactoring to use async traits
- The current approach is a stepping stone toward full async support

## API Usage

### C2paAsyncReader (Recommended)

This is the recommended approach for async streaming. It reads data in chunks and provides proper async JavaScript API:

```javascript
import { C2paAsyncReader, JsStreamCallbacks } from './pkg/c2pa_wasm.js';

// Create streaming callbacks
const callbacks = new JsStreamCallbacks(
    // Read callback: returns Promise<Uint8Array>
    async (bufferSize) => {
        const chunk = await readChunkFromSource(bufferSize);
        return new Uint8Array(chunk);
    },
    // Seek callback: returns Promise<number>
    async (offset, mode) => {
        const newPosition = await seekInSource(offset, mode);
        return newPosition;
    },
    // Write callback (optional): returns Promise<number>
    async (data) => {
        const bytesWritten = await writeToDestination(data);
        return bytesWritten;
    },
    // Flush callback (optional): returns Promise<void>
    async () => {
        await flushDestination();
    }
);

// Create reader and process C2PA data
const reader = new C2paAsyncReader(callbacks);
const c2paReader = await reader.read_c2pa_chunked('image/jpeg');

// Use the reader
const manifestJson = c2paReader.json();
const manifest = JSON.parse(manifestJson);
console.log('Manifest:', manifest);
```

### C2paStreamReader (Advanced)

This provides lower-level streaming with JavaScript callbacks. Currently requires synchronous callbacks:

```javascript
import { C2paStreamReader, JsStreamCallbacks } from './pkg/c2pa_wasm.js';

// Create streaming callbacks (must be synchronous for now)
const callbacks = new JsStreamCallbacks(
    // Read callback: returns Uint8Array directly
    (bufferSize) => {
        const chunk = readChunkFromSourceSync(bufferSize);
        return new Uint8Array(chunk);
    },
    // Seek callback: returns number directly
    (offset, mode) => {
        return seekInSourceSync(offset, mode);
    },
    // Write callback (optional)
    (data) => {
        return writeToDestinationSync(data);
    },
    // Flush callback (optional)
    () => {
        flushDestinationSync();
    }
);

// Create reader and process C2PA data
const streamReader = new C2paStreamReader(callbacks);
const c2paReader = await streamReader.read_c2pa('image/jpeg');

// Use the reader
const manifestJson = c2paReader.json();
console.log('Manifest:', JSON.parse(manifestJson));
```

## Example: Reading from a File

```javascript
import { C2paAsyncReader, JsStreamCallbacks } from './pkg/c2pa_wasm.js';

async function readC2paFromFile(file) {
    let position = 0;
    
    const callbacks = new JsStreamCallbacks(
        // Read callback
        async (bufferSize) => {
            const chunk = file.slice(position, position + bufferSize);
            const arrayBuffer = await chunk.arrayBuffer();
            const uint8Array = new Uint8Array(arrayBuffer);
            position += uint8Array.length;
            return uint8Array;
        },
        // Seek callback
        async (offset, mode) => {
            switch (mode) {
                case 0: // Start
                    position = offset;
                    break;
                case 1: // Current
                    position += offset;
                    break;
                case 2: // End
                    position = file.size + offset;
                    break;
            }
            return position;
        }
    );
    
    const reader = new C2paAsyncReader(callbacks);
    return await reader.read_c2pa_chunked('image/jpeg');
}

// Usage
const fileInput = document.getElementById('file-input');
fileInput.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (file) {
        try {
            const reader = await readC2paFromFile(file);
            const manifest = JSON.parse(reader.json());
            console.log('C2PA Manifest:', manifest);
        } catch (error) {
            console.error('Error reading C2PA data:', error);
        }
    }
});
```

## Example: Reading from a ReadableStream

```javascript
import { C2paAsyncReader, JsStreamCallbacks } from './pkg/c2pa_wasm.js';

async function readC2paFromStream(stream) {
    const reader = stream.getReader();
    let buffer = new Uint8Array(0);
    let position = 0;
    let done = false;
    
    const callbacks = new JsStreamCallbacks(
        // Read callback
        async (bufferSize) => {
            // Ensure we have enough data in buffer
            while (buffer.length - position < bufferSize && !done) {
                const { value, done: streamDone } = await reader.read();
                done = streamDone;
                if (value) {
                    const newBuffer = new Uint8Array(buffer.length + value.length);
                    newBuffer.set(buffer);
                    newBuffer.set(value, buffer.length);
                    buffer = newBuffer;
                }
            }
            
            // Return requested chunk
            const end = Math.min(position + bufferSize, buffer.length);
            const chunk = buffer.slice(position, end);
            position = end;
            return chunk;
        },
        // Seek callback (limited support for streams)
        async (offset, mode) => {
            if (mode === 0) { // Start
                position = offset;
            } else if (mode === 1) { // Current
                position += offset;
            }
            // Note: End seek not supported for streams
            return position;
        }
    );
    
    const c2paReader = new C2paAsyncReader(callbacks);
    return await c2paReader.read_c2pa_chunked('image/jpeg');
}
```

## Future Improvements

When the C2PA SDK is refactored to support async traits natively, the following improvements will be possible:

1. **True Async Streaming**: The `C2paStreamReader` will support fully async JavaScript callbacks
2. **Better Memory Efficiency**: Streaming operations won't need to buffer data
3. **Backpressure Support**: Proper flow control for large assets
4. **Cancellation**: Ability to cancel streaming operations

## Migration Path

1. **Current (v0.1)**: Use `C2paAsyncReader` for async streaming with chunked loading
2. **Future (v0.2)**: Enhanced `C2paStreamReader` with true async callback support
3. **Future (v0.3)**: Full async C2PA SDK with native streaming traits

## Limitations and Tradeoffs

### Current Limitations:
- `C2paStreamReader` requires synchronous JavaScript callbacks
- Cannot fully stream large assets without some memory usage
- Seek operations may be limited depending on the source

### Tradeoffs:
- **Memory vs. Performance**: Chunked reading uses more memory than true streaming but provides better compatibility
- **Sync vs. Async**: The current sync bridge provides compatibility but limits async capabilities
- **Complexity vs. Functionality**: The API provides powerful streaming but requires careful callback implementation

## Error Handling

```javascript
try {
    const reader = new C2paAsyncReader(callbacks);
    const c2paReader = await reader.read_c2pa_chunked(format);
    // Process C2PA data
} catch (error) {
    if (error.message.includes('Async promises not supported')) {
        console.error('Use C2paAsyncReader for async operations');
    } else if (error.message.includes('Failed to create reader')) {
        console.error('Invalid C2PA data or unsupported format');
    } else {
        console.error('Streaming error:', error);
    }
}
```

This streaming API provides a foundation for efficient C2PA processing in JavaScript while maintaining compatibility with the current sync C2PA SDK. It represents a significant step toward true async streaming support.
