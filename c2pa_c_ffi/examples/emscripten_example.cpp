// Example: Using c2pa C library in an Emscripten C++ project
// Build: see build_emscripten_example.sh
//
// HTTP resolver note: emscripten_fetch in SYNCHRONOUS mode is only available
// from a Web Worker, not the browser main thread. Under Node.js there is no
// such restriction.

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "c2pa.h"

#ifdef __EMSCRIPTEN__
#include <emscripten/fetch.h>
#endif

// RAII wrapper that calls c2pa_string_free on destruction.
class C2paString {
    char* str_;
public:
    explicit C2paString(char* str) : str_(str) {}
    ~C2paString() { if (str_) c2pa_string_free(str_); }
    const char* get() const { return str_; }
    bool is_null() const { return str_ == nullptr; }
    C2paString(const C2paString&) = delete;
    C2paString& operator=(const C2paString&) = delete;
};

// ---------------------------------------------------------------------------
// Stream helpers — shared by read_with_stream() and read_with_http_resolver()
// ---------------------------------------------------------------------------

struct MemStream { const uint8_t* data; size_t size; size_t pos; };

static ReadCallback mem_read = [](StreamContext* c, uint8_t* buf, intptr_t len) -> intptr_t {
    auto* s = reinterpret_cast<MemStream*>(c);
    size_t avail  = s->size - s->pos;
    size_t n      = static_cast<size_t>(len) < avail ? static_cast<size_t>(len) : avail;
    if (n) { memcpy(buf, s->data + s->pos, n); s->pos += n; }
    return static_cast<intptr_t>(n);
};

static SeekCallback mem_seek = [](StreamContext* c, intptr_t off, C2paSeekMode mode) -> intptr_t {
    auto* s = reinterpret_cast<MemStream*>(c);
    size_t new_pos;
    switch (mode) {
        case Start:   new_pos = static_cast<size_t>(off); break;
        case Current: new_pos = static_cast<size_t>(static_cast<intptr_t>(s->pos) + off); break;
        case End:     new_pos = static_cast<size_t>(static_cast<intptr_t>(s->size) + off); break;
        default:      return -1;
    }
    if (new_pos > s->size) return -1;
    s->pos = new_pos;
    return static_cast<intptr_t>(new_pos);
};

// ---------------------------------------------------------------------------
// Example 1: read from file path
// ---------------------------------------------------------------------------

static void read_from_file(const char* path) {
    std::cout << "\n[1] Reading manifest from file: " << path << std::endl;
    C2paString manifest(c2pa_read_file(path, nullptr));
    if (manifest.is_null()) {
        C2paString err(c2pa_error());
        std::cerr << "Error: " << err.get() << std::endl;
        return;
    }
    std::cout << manifest.get() << std::endl;
}

// ---------------------------------------------------------------------------
// Example 2: read from an in-memory stream
// ---------------------------------------------------------------------------

static void read_from_stream(const uint8_t* data, size_t size) {
    std::cout << "\n[2] Reading manifest from memory stream" << std::endl;
    MemStream ctx = { data, size, 0 };
    C2paStream* stream = c2pa_create_stream(
        reinterpret_cast<StreamContext*>(&ctx), mem_read, mem_seek, nullptr, nullptr);
    if (!stream) { std::cerr << "Failed to create stream" << std::endl; return; }

    C2paReader* reader = c2pa_reader_from_stream("image/jpeg", stream);
    if (reader) {
        C2paString json(c2pa_reader_json(reader));
        std::cout << json.get() << std::endl;
        std::cout << "Embedded: " << (c2pa_reader_is_embedded(reader) ? "yes" : "no") << std::endl;
        c2pa_free(reader);
    } else {
        C2paString err(c2pa_error());
        std::cerr << "Error: " << err.get() << std::endl;
    }
    c2pa_release_stream(stream);
}

// ---------------------------------------------------------------------------
// Example 3: read with a custom HTTP resolver (emscripten_fetch)
//   - Exercises remote manifest fetching, OCSP, timestamps, etc.
//   - Must run from a Web Worker in the browser; no restriction under Node.js.
// ---------------------------------------------------------------------------

#ifdef __EMSCRIPTEN__

// Parse "Name: Value\n..." into a NULL-terminated char* array for
// emscripten_fetch_attr_t::requestHeaders.
static std::vector<const char*> parse_headers(const std::string& raw) {
    static std::vector<std::string> storage;
    storage.clear();
    std::vector<const char*> result;
    std::istringstream ss(raw);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty()) continue;
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        storage.push_back(line.substr(0, colon));
        storage.push_back(line.substr(colon + 2));
    }
    for (auto& s : storage) result.push_back(s.c_str());
    result.push_back(nullptr);
    return result;
}

static int emscripten_http_handler(
    void* /*ctx*/, const C2paHttpRequest* req, C2paHttpResponse* resp)
{
    emscripten_fetch_attr_t attr;
    emscripten_fetch_attr_init(&attr);
    attr.attributes = EMSCRIPTEN_FETCH_LOAD_TO_MEMORY | EMSCRIPTEN_FETCH_SYNCHRONOUS;
    strncpy(attr.requestMethod, req->method, sizeof(attr.requestMethod) - 1);
    attr.requestMethod[sizeof(attr.requestMethod) - 1] = '\0';
    if (req->body && req->body_len > 0) {
        attr.requestData     = reinterpret_cast<const char*>(req->body);
        attr.requestDataSize = req->body_len;
    }
    auto header_vec = parse_headers(req->headers ? req->headers : "");
    if (header_vec.size() > 1) attr.requestHeaders = header_vec.data();

    emscripten_fetch_t* fetch = emscripten_fetch(&attr, req->url);
    if (!fetch) { c2pa_error_set_last("emscripten_fetch returned null"); return -1; }

    resp->status   = static_cast<int32_t>(fetch->status);
    resp->body_len = static_cast<size_t>(fetch->numBytes);
    resp->body     = static_cast<uint8_t*>(malloc(resp->body_len));
    memcpy(resp->body, fetch->data, resp->body_len);
    emscripten_fetch_close(fetch);
    return 0;
}

static void read_with_http_resolver(const uint8_t* data, size_t size) {
    std::cout << "\n[3] Reading remote manifest with custom HTTP resolver" << std::endl;

    C2paContextBuilder* builder  = c2pa_context_builder_new();
    C2paHttpResolver*   resolver = c2pa_http_resolver_create(nullptr, emscripten_http_handler);
    if (c2pa_context_builder_set_http_resolver(builder, resolver) != 0) {
        C2paString err(c2pa_error());
        std::cerr << "set_http_resolver failed: " << err.get() << std::endl;
        c2pa_free(builder);
        return;
    }
    // resolver is owned by builder after set_http_resolver — do NOT free it.

    C2paContext* ctx = c2pa_context_builder_build(builder);
    if (!ctx) {
        C2paString err(c2pa_error());
        std::cerr << "context build failed: " << err.get() << std::endl;
        return;
    }

    MemStream sctx = { data, size, 0 };
    C2paStream* stream = c2pa_create_stream(
        reinterpret_cast<StreamContext*>(&sctx), mem_read, mem_seek, nullptr, nullptr);
    if (!stream) { std::cerr << "Failed to create stream" << std::endl; c2pa_free(ctx); return; }

    // c2pa_reader_from_context + c2pa_reader_with_stream: the first call sets
    // up the context (HTTP resolver), the second attaches the data stream.
    C2paReader* reader = c2pa_reader_from_context(ctx);
    if (reader) reader = c2pa_reader_with_stream(reader, "image/jpeg", stream);

    if (reader) {
        C2paString json(c2pa_reader_json(reader));
        std::cout << json.get() << std::endl;
        c2pa_free(reader);
    } else {
        C2paString err(c2pa_error());
        std::cerr << "Error: " << err.get() << std::endl;
    }

    c2pa_release_stream(stream);
    c2pa_free(ctx);
}

#endif // __EMSCRIPTEN__

// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    std::cout << "=== C2PA Emscripten Example ===" << std::endl;
    C2paString version(c2pa_version());
    std::cout << "Version: " << version.get() << std::endl;

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <image.jpg>" << std::endl;
        return 0;
    }

    const char* path = argv[1];

    // Read file into memory once; reuse for stream-based examples.
    std::vector<uint8_t> image_data;
    {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (f) {
            auto sz = f.tellg();
            f.seekg(0);
            image_data.resize(static_cast<size_t>(sz));
            f.read(reinterpret_cast<char*>(image_data.data()), sz);
        }
    }

    read_from_file(path);

    if (!image_data.empty()) {
        read_from_stream(image_data.data(), image_data.size());
#ifdef __EMSCRIPTEN__
        read_with_http_resolver(image_data.data(), image_data.size());
#endif
    }

    std::cout << "\n=== Done ===" << std::endl;
    return 0;
}
