:: 1. Configure the project for Windows using MSVC & Ninja
cmake --preset ci-windows

:: 2. Build all 6 service binaries and tests
cmake --build --preset ci-windows

:: 3. Run CTest test suite
ctest --preset ci-windows
