#pragma once
#include <algorithm>
#include <cstdint>
#include <cve.h>
#include <string>
#include <vector>

enum class Color : uint8_t { Black, Red };

template <typename Key> struct RedBlackNode {
  RedBlackNode *left = nullptr;
  RedBlackNode *right = nullptr;
  Color color = Color::Black;
  Key key;
  std::vector<uint32_t> records;
};

// left leaning red black tree, same rules as a normal one but red links only
// lean left so insert only has 3 cases to fix. records are indexes into the
// vector of CveRecords, same key twice just adds to that node's list
template <typename Key> class RedBlackTree {
public:
  using Node = RedBlackNode<Key>;

  RedBlackTree() = default;
  RedBlackTree(const RedBlackTree &) = delete;
  RedBlackTree &operator=(const RedBlackTree &) = delete;
  ~RedBlackTree() { destroy(root); }

  void insert(const Key &key, uint32_t record) {
    root = insert(root, key, record);
    root->color = Color::Black;
  }

  // nullptr if the key isn't in the tree
  const std::vector<uint32_t> *find(const Key &key) const {
    Node *cur = root;
    while (cur) {
      if (key < cur->key)
        cur = cur->left;
      else if (cur->key < key)
        cur = cur->right;
      else
        return &cur->records;
    }
    return nullptr;
  }

  // visit(key, records) for every node in sorted order
  template <typename F> void inorder(F visit) const { inorder(root, visit); }

  // same thing but only keys from lo to hi, good for date ranges
  template <typename F> void range(const Key &lo, const Key &hi, F visit) const {
    range(root, lo, hi, visit);
  }

  size_t size() const { return count; }
  int height() const { return height(root); }

  // checks the red black rules, mostly for the tests
  bool valid() const {
    return !isRed(root) && blackHeight(root) != -1;
  }

private:
  Node *root = nullptr;
  size_t count = 0;

  static bool isRed(Node *n) { return n && n->color == Color::Red; }

  static Node *rotateLeft(Node *h) {
    Node *x = h->right;
    h->right = x->left;
    x->left = h;
    x->color = h->color;
    h->color = Color::Red;
    return x;
  }

  static Node *rotateRight(Node *h) {
    Node *x = h->left;
    h->left = x->right;
    x->right = h;
    x->color = h->color;
    h->color = Color::Red;
    return x;
  }

  static void flipColors(Node *h) {
    h->color = Color::Red;
    h->left->color = Color::Black;
    h->right->color = Color::Black;
  }

  Node *insert(Node *h, const Key &key, uint32_t record) {
    if (!h) {
      count++;
      Node *n = new Node;
      n->key = key;
      n->color = Color::Red;
      n->records.push_back(record);
      return n;
    }

    if (key < h->key)
      h->left = insert(h->left, key, record);
    else if (h->key < key)
      h->right = insert(h->right, key, record);
    // a cve can list the same cpe a bunch of times, only keep it once
    else if (h->records.back() != record)
      h->records.push_back(record);

    // fix things on the way back up
    if (isRed(h->right) && !isRed(h->left))
      h = rotateLeft(h);
    if (isRed(h->left) && isRed(h->left->left))
      h = rotateRight(h);
    if (isRed(h->left) && isRed(h->right))
      flipColors(h);
    return h;
  }

  template <typename F> static void inorder(Node *n, F &visit) {
    if (!n)
      return;
    inorder(n->left, visit);
    visit(n->key, n->records);
    inorder(n->right, visit);
  }

  template <typename F>
  static void range(Node *n, const Key &lo, const Key &hi, F &visit) {
    if (!n)
      return;
    if (lo < n->key)
      range(n->left, lo, hi, visit);
    if (!(n->key < lo) && !(hi < n->key))
      visit(n->key, n->records);
    if (n->key < hi)
      range(n->right, lo, hi, visit);
  }

  static int height(Node *n) {
    if (!n)
      return 0;
    return 1 + std::max(height(n->left), height(n->right));
  }

  // -1 means a rule got broken somewhere below n
  static int blackHeight(Node *n) {
    if (!n)
      return 1;
    if (isRed(n) && (isRed(n->left) || isRed(n->right)))
      return -1;
    int l = blackHeight(n->left), r = blackHeight(n->right);
    if (l == -1 || r == -1 || l != r)
      return -1;
    return l + (isRed(n) ? 0 : 1);
  }

  static void destroy(Node *n) {
    if (!n)
      return;
    destroy(n->left);
    destroy(n->right);
    delete n;
  }
};

// one tree keyed by cpe (vendor:product) and one keyed by published date,
// both point back into records by index
inline void buildRedBlackTrees(const std::vector<CveRecord> &records,
                               RedBlackTree<std::string> &byCpe,
                               RedBlackTree<int64_t> &byDate) {
  for (uint32_t i = 0; i < records.size(); i++) {
    byDate.insert(records[i].published, i);
    for (const Cpe &cpe : records[i].cpes)
      byCpe.insert(cpeKey(cpe), i);
  }
}
