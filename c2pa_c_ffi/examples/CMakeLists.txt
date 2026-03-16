cmake_minimum_required(VERSION 3.13)
project(C2PAEmscriptenExample)

if(NOT EMSCRIPTEN)
    message(FATAL_ERROR "This project requires Emscripten. Use: emcmake cmake")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# C2PA_ROOT must point to the cargo workspace root (where target/ lives).
set(C2PA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH "Path to c2pa-rs workspace root")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(C2PA_LIB_DIR "${C2PA_ROOT}/target/wasm32-unknown-emscripten/debug")
else()
    set(C2PA_LIB_DIR "${C2PA_ROOT}/target/wasm32-unknown-emscripten/release")
endif()

set(C2PA_LIBRARY "${C2PA_LIB_DIR}/libc2pa_c.a")

if(NOT EXISTS "${C2PA_LIBRARY}")
    message(FATAL_ERROR
        "c2pa library not found: ${C2PA_LIBRARY}\n"
        "Build it first:\n"
        "  cargo +nightly build -Z build-std=std,panic_unwind \\\n"
        "    -p c2pa-c-ffi --target wasm32-unknown-emscripten --release \\\n"
        "    --no-default-features --features rust_native_crypto,file_io"
    )
endif()

add_executable(c2pa_example emscripten_example.cpp)
target_include_directories(c2pa_example PRIVATE ${C2PA_LIB_DIR})
target_link_libraries(c2pa_example ${C2PA_LIBRARY})

# -pthread and -fwasm-exceptions must match the Rust library's compile flags
# (set in .cargo/config.toml for the wasm32-unknown-emscripten target).
set(EMSCRIPTEN_LINK_FLAGS
    "-pthread"
    "-fwasm-exceptions"
    "-s WASM=1"
    "-s USE_PTHREADS=1"
    "-s ALLOW_MEMORY_GROWTH=1"
    "-s INITIAL_MEMORY=256MB"
    "-s MAXIMUM_MEMORY=2GB"
    "-s EXPORTED_FUNCTIONS=['_main']"
    "-s EXPORTED_RUNTIME_METHODS=['ccall','cwrap','FS']"
    "-s FETCH=1"
    "-s ENVIRONMENT=node,worker"
    "-s NODERAWFS=1"
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    list(APPEND EMSCRIPTEN_LINK_FLAGS "-g" "-s ASSERTIONS=1" "-s SAFE_HEAP=1")
else()
    list(APPEND EMSCRIPTEN_LINK_FLAGS "-O3" "-s ASSERTIONS=0")
endif()

string(REPLACE ";" " " EMSCRIPTEN_LINK_FLAGS_STR "${EMSCRIPTEN_LINK_FLAGS}")
set_target_properties(c2pa_example PROPERTIES
    LINK_FLAGS "${EMSCRIPTEN_LINK_FLAGS_STR}"
    SUFFIX ".js"
)

install(TARGETS c2pa_example RUNTIME DESTINATION bin)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/c2pa_example.js"
    "${CMAKE_CURRENT_BINARY_DIR}/c2pa_example.wasm"
    "${CMAKE_CURRENT_BINARY_DIR}/c2pa_example.worker.js"
    DESTINATION bin
)
