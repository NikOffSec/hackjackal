#pragma once
#include <algorithm>
#include <cstdint>
#include <cve.h>
#include <string>
#include <utility>
#include <vector>

template <typename Key> struct SplayNode {
  SplayNode *left = nullptr;
  SplayNode *right = nullptr;
  Key key;
  std::vector<uint32_t> records;
};

// top down splay tree, same interface as the red black one so we can swap
// them in the gui. every insert and find splays the key to the root so stuff
// you look up a lot stays near the top
template <typename Key> class SplayTree {
public:
  using Node = SplayNode<Key>;

  SplayTree() = default;
  SplayTree(const SplayTree &) = delete;
  SplayTree &operator=(const SplayTree &) = delete;
  ~SplayTree() { destroy(); }

  void insert(const Key &key, uint32_t record) {
    if (!root) {
      root = newNode(key, record);
      return;
    }

    root = splay(root, key);
    if (!(key < root->key) && !(root->key < key)) {
      // same deal as the red black one, a cve can list a cpe more than once
      if (root->records.back() != record)
        root->records.push_back(record);
      return;
    }

    // split the old root around the new node
    Node *n = newNode(key, record);
    if (key < root->key) {
      n->left = root->left;
      n->right = root;
      root->left = nullptr;
    } else {
      n->right = root->right;
      n->left = root;
      root->right = nullptr;
    }
    root = n;
  }

  // not const like the red black find since splaying moves things around
  const std::vector<uint32_t> *find(const Key &key) {
    if (!root)
      return nullptr;
    root = splay(root, key);
    if (key < root->key || root->key < key)
      return nullptr;
    return &root->records;
  }

  // adds every node a find for key walks through, for the visualizer. this
  // one doesn't splay, so call it before find or the path will be gone
  void tracePath(const Key &key, std::vector<const Node *> &path) const {
    const Node *cur = root;
    while (cur) {
      path.push_back(cur);
      if (key < cur->key)
        cur = cur->left;
      else if (cur->key < key)
        cur = cur->right;
      else
        return;
    }
  }

  // the traversals use a stack instead of recursion because sorted inserts
  // turn the tree into one long line and that'd blow the call stack

  template <typename F> void inorder(F visit) const {
    std::vector<Node *> stack;
    Node *cur = root;
    while (cur || !stack.empty()) {
      while (cur) {
        stack.push_back(cur);
        cur = cur->left;
      }
      cur = stack.back();
      stack.pop_back();
      visit(cur->key, cur->records);
      cur = cur->right;
    }
  }

  template <typename F> void range(const Key &lo, const Key &hi, F visit) const {
    std::vector<Node *> stack;
    Node *cur = root;
    while (cur || !stack.empty()) {
      // no point going left if everything over there is below lo
      while (cur) {
        stack.push_back(cur);
        cur = cur->key < lo ? nullptr : cur->left;
      }
      cur = stack.back();
      stack.pop_back();
      if (hi < cur->key)
        return;
      if (!(cur->key < lo))
        visit(cur->key, cur->records);
      cur = cur->right;
    }
  }

  size_t size() const { return count; }

  int height() const {
    int best = 0;
    std::vector<std::pair<Node *, int>> stack;
    if (root)
      stack.push_back({root, 1});
    while (!stack.empty()) {
      auto [n, h] = stack.back();
      stack.pop_back();
      best = std::max(best, h);
      if (n->left)
        stack.push_back({n->left, h + 1});
      if (n->right)
        stack.push_back({n->right, h + 1});
    }
    return best;
  }

  // splay trees don't have balance rules, so just make sure it's still a
  // proper bst and the count matches
  bool valid() const {
    bool ok = true;
    bool first = true;
    size_t seen = 0;
    const Key *prev = nullptr;
    inorder([&](const Key &key, const std::vector<uint32_t> &) {
      if (!first && !(*prev < key))
        ok = false;
      first = false;
      prev = &key;
      seen++;
    });
    return ok && seen == count;
  }

private:
  Node *root = nullptr;
  size_t count = 0;

  Node *newNode(const Key &key, uint32_t record) {
    count++;
    Node *n = new Node;
    n->key = key;
    n->records.push_back(record);
    return n;
  }

  // walks down toward key, hanging everything smaller off a left tree and
  // everything bigger off a right tree, then puts them back together under
  // whatever node we stopped at. if key isn't there you get the last node
  // on the search path as the root instead
  static Node *splay(Node *t, const Key &key) {
    Node header; // header.right ends up as the left tree, header.left the right
    Node *l = &header;
    Node *r = &header;

    while (true) {
      if (key < t->key) {
        if (!t->left)
          break;
        if (key < t->left->key) { // zig zig, rotate right first
          Node *y = t->left;
          t->left = y->right;
          y->right = t;
          t = y;
          if (!t->left)
            break;
        }
        r->left = t;
        r = t;
        t = t->left;
      } else if (t->key < key) {
        if (!t->right)
          break;
        if (t->right->key < key) { // zag zag, rotate left first
          Node *y = t->right;
          t->right = y->left;
          y->left = t;
          t = y;
          if (!t->right)
            break;
        }
        l->right = t;
        l = t;
        t = t->right;
      } else {
        break;
      }
    }

    l->right = t->left;
    r->left = t->right;
    t->left = header.right;
    t->right = header.left;
    return t;
  }

  void destroy() {
    std::vector<Node *> stack;
    if (root)
      stack.push_back(root);
    while (!stack.empty()) {
      Node *n = stack.back();
      stack.pop_back();
      if (n->left)
        stack.push_back(n->left);
      if (n->right)
        stack.push_back(n->right);
      delete n;
    }
    root = nullptr;
  }
};

// splay version of buildRedBlackTrees, same keys so the results line up
inline void buildSplayTrees(const std::vector<CveRecord> &records,
                            SplayTree<std::string> &byCpe,
                            SplayTree<int64_t> &byDate) {
  for (uint32_t i = 0; i < records.size(); i++) {
    byDate.insert(records[i].published, i);
    for (const Cpe &cpe : records[i].cpes)
      byCpe.insert(cpeKey(cpe), i);
  }
}
