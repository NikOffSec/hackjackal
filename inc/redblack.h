#include <cstdint>
#include <vector>

enum class Color : uint8_t { Black, Red };

template <typename Key> struct RedBlackNode {
  RedBlackNode *left = nullptr;
  RedBlackNode *right = nullptr;
  Color color = Color::Black;
  Key key;
  std::vector<uint32_t> records;
};
