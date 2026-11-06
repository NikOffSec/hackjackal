
# Usage
Download the NVD feeds into data/ first (about 3 GB, the app reads every yearly
feed and needs around 2 GB of free memory):


*python3 scripts/download_nvd.py*


How to compile and run the binary


*cmake -B build -G Ninja*


To build and run the binary:
*cmake --build build && ./build/hackjackal*


To build and run the test cases:
*ctest --test-dir build*
