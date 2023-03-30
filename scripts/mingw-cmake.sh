cmake -E remove_directory build
cmake -E make_directory build
cd build
cmake .. -DENABLE_DOCS=OFF -DDTLS_BACKEND=openssl -DWARNING_TO_ERROR=ON
cmake --build .
cmake --build . -- install
