#pragma once
#include <cstddef>
#include <cstdint>
#include <cve.h>
#include <functional>
#include <redblack.h>
#include <splay.h>
#include <string>
#include <vector>

enum class TreeKind { RedBlack, Splay };
enum class KeyKind { Date, Cpe };

// the records plus all 4 trees, not movable so it lives behind a pointer
struct CveStore {
  std::vector<CveRecord> records;
  RedBlackTree<std::string> rbCpe;
  RedBlackTree<int64_t> rbDate;
  SplayTree<std::string> splayCpe;
  SplayTree<int64_t> splayDate;

  void build();
};

struct PathStep {
  std::string label;
  bool red;
  bool wentLeft; // this node is the left child of the one before it
};

struct SearchResult {
  std::vector<PathStep> path;
  std::vector<uint32_t> matches;
  double micros = 0.0;
};

// every yearly feed in dir put together, oldest first. the modified and recent
// feeds repeat CVEs that are already in those, so they get skipped, and so do
// records NVD has marked as rejected. progress
// gets called with how many feeds are done and how many there are
std::vector<CveRecord>
loadYearFeeds(const std::string &dir,
              const std::function<void(size_t, size_t)> &progress = {});

// a full timestamp gives lo == hi, a plain date gives that whole day. false if
// the text isn't YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS
bool parseDateQuery(const std::string &text, int64_t &lo, int64_t &hi);

// query is expected to have been checked with parseDateQuery for date keys
SearchResult runSearch(CveStore &store, TreeKind tree, KeyKind key,
                       const std::string &query);

// random left and right steps so the animation can be tested at any length
std::vector<PathStep> fakePath(size_t nodes, bool colored, uint32_t seed);

std::string trimmed(const std::string &text);
std::string formatDate(int64_t seconds);
std::string buildCveText(const CveRecord &record);

// where the head is at time t: all but the last 3 hops in a fast ease-out,
// then the last 3 at a fixed slow pace
struct HopState {
  size_t node;  // the node it most recently left
  double phase; // 0 to 1 toward the next node
  bool fast;
  bool done;
  double fastLeft; // 1 at the start of the fast phase down to 0 at the end
};

HopState hopAt(double t, size_t hops);
double animationLength(size_t hops);
