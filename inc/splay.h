#include <cstdint>
#include <string>
#include <vector>

template <typename Key> struct SplayNode {
  SplayNode *left = nullptr;
  SplayNode *right = nullptr;
  Key key;
  std::vector<uint32_t> records;
};
