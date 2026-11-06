#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <format>
#include <future>
#include <mutex>
#include <random>
#include <search.h>
#include <stdexcept>
#include <thread>

static constexpr unsigned LOAD_THREADS_MAX =
    4; // limit to 4 so we don't take up to much ram for little potato computers
static constexpr size_t LABEL_MAX = 11;
static constexpr size_t CPE_LINES_MAX = 50;
static constexpr double FAST_TIME = 1.5;
static constexpr double SLOW_HOP_TIME = 0.3;
static constexpr size_t SLOW_HOPS = 3;

void CveStore::build() {
  // the trees only read records, so the two kinds can build side by side
  std::future<void> splay = std::async(std::launch::async, [this] {
    buildSplayTrees(records, splayCpe, splayDate);
  });
  buildRedBlackTrees(records, rbCpe, rbDate);
  splay.get();
}

std::vector<CveRecord>
loadYearFeeds(const std::string &dir,
              const std::function<void(size_t, size_t)> &progress) {
  namespace fs = std::filesystem;
  const std::string prefix = "nvdcve-2.0-", suffix = ".json";
  std::vector<fs::path> feeds;
  std::error_code ec;
  for (const fs::directory_entry &entry : fs::directory_iterator(dir, ec)) {
    std::string name = entry.path().filename().string();
    if (name.size() != prefix.size() + 4 + suffix.size() ||
        !name.starts_with(prefix) || !name.ends_with(suffix))
      continue;
    std::string year = name.substr(prefix.size(), 4);
    if (std::all_of(year.begin(), year.end(),
                    [](unsigned char c) { return std::isdigit(c); }))
      feeds.push_back(entry.path());
  }
  if (feeds.empty())
    throw std::runtime_error("no yearly feeds in " + dir);
  std::sort(feeds.begin(), feeds.end());

  // the workers grab feeds newest first since those are the biggest, each one
  // holds its whole file in memory so that's what the thread limit is for
  std::vector<std::vector<CveRecord>> years(feeds.size());
  std::atomic<size_t> started{0};
  std::mutex progressMutex;
  size_t done = 0;
  auto loadFeeds = [&] {
    for (size_t n; (n = started++) < feeds.size();) {
      size_t i = feeds.size() - 1 - n;
      std::vector<CveRecord> year = loadRecords(feeds[i].string());
      // withdrawn IDs, NVD keeps them around but they aren't real
      // vulnerabilities
      std::erase_if(year,
                    [](const CveRecord &r) { return r.status == "Rejected"; });
      years[i] = std::move(year);

      std::lock_guard lock(progressMutex);
      done++;
      if (progress)
        progress(done, feeds.size());
    }
  };

  if (progress)
    progress(0, feeds.size());
  unsigned threads =
      std::clamp(std::thread::hardware_concurrency(), 1u, LOAD_THREADS_MAX);
  std::vector<std::future<void>> workers;
  for (unsigned i = 0; i < threads; i++)
    workers.push_back(std::async(std::launch::async, loadFeeds));
  // get rethrows if that worker failed, the rest still finish first
  for (std::future<void> &worker : workers)
    worker.get();

  size_t total = 0;
  for (const std::vector<CveRecord> &year : years)
    total += year.size();

  std::vector<CveRecord> records;
  records.reserve(total);
  for (std::vector<CveRecord> &year : years) {
    records.insert(records.end(), std::make_move_iterator(year.begin()),
                   std::make_move_iterator(year.end()));
    year = {};
  }
  return records;
}

static std::string labelFor(int64_t key) {
  return formatDate(key).substr(0, 10);
}

static std::string labelFor(const std::string &key) {
  if (key.size() <= LABEL_MAX)
    return key;
  // back up so a multi byte character doesn't get cut in half
  size_t cut = LABEL_MAX - 2;
  while (cut > 0 && (key[cut] & 0xC0) == 0x80)
    cut--;
  return key.substr(0, cut) + "..";
}

template <typename Key> static bool isRed(const RedBlackNode<Key> *n) {
  return n->color == Color::Red;
}

template <typename Key> static bool isRed(const SplayNode<Key> *) {
  return false;
}

template <typename Tree, typename Key>
static SearchResult searchTree(Tree &tree, const Key &lo, const Key &hi) {
  using Node = typename Tree::Node;
  SearchResult result;

  // the path has to come first, find can splay it away
  std::vector<const Node *> nodes;
  tree.tracePath(lo, nodes);

  // the first node inside [lo, hi] on the way to lo is the top of that range
  auto stop = std::find_if(nodes.begin(), nodes.end(), [&](const Node *n) {
    return !(n->key < lo) && !(hi < n->key);
  });
  if (stop != nodes.end())
    nodes.erase(stop + 1, nodes.end());

  result.path.reserve(nodes.size());
  for (size_t i = 0; i < nodes.size(); i++)
    result.path.push_back({labelFor(nodes[i]->key), isRed(nodes[i]),
                           i > 0 && nodes[i - 1]->left == nodes[i]});

  auto start = std::chrono::steady_clock::now();
  if (lo < hi) {
    tree.find(lo);
    tree.range(lo, hi, [&](const Key &, const std::vector<uint32_t> &records) {
      result.matches.insert(result.matches.end(), records.begin(),
                            records.end());
    });
  } else if (const std::vector<uint32_t> *records = tree.find(lo)) {
    result.matches = *records;
  }
  auto end = std::chrono::steady_clock::now();
  result.micros =
      std::chrono::duration<double, std::micro>(end - start).count();
  return result;
}

SearchResult runSearch(CveStore &store, TreeKind tree, KeyKind key,
                       const std::string &query) {
  if (key == KeyKind::Cpe)
    return tree == TreeKind::RedBlack
               ? searchTree(store.rbCpe, query, query)
               : searchTree(store.splayCpe, query, query);

  int64_t lo = 0, hi = 0;
  if (!parseDateQuery(query, lo, hi))
    return {};
  return tree == TreeKind::RedBlack ? searchTree(store.rbDate, lo, hi)
                                    : searchTree(store.splayDate, lo, hi);
}

static bool digitsAt(const std::string &s, size_t at, size_t count, int &out) {
  out = 0;
  for (size_t i = at; i < at + count; i++) {
    if (!std::isdigit((unsigned char)s[i]))
      return false;
    out = out * 10 + (s[i] - '0');
  }
  return true;
}

bool parseDateQuery(const std::string &text, int64_t &lo, int64_t &hi) {
  bool hasTime = text.size() == 19;
  if (!hasTime && text.size() != 10)
    return false;

  int y, mo, d, hh = 0, mm = 0, ss = 0;
  if (!digitsAt(text, 0, 4, y) || text[4] != '-' || !digitsAt(text, 5, 2, mo) ||
      text[7] != '-' || !digitsAt(text, 8, 2, d))
    return false;
  if (hasTime &&
      ((text[10] != 'T' && text[10] != ' ') || !digitsAt(text, 11, 2, hh) ||
       text[13] != ':' || !digitsAt(text, 14, 2, mm) || text[16] != ':' ||
       !digitsAt(text, 17, 2, ss)))
    return false;
  if (hh > 23 || mm > 59 || ss > 59)
    return false;

  using namespace std::chrono;
  year_month_day ymd = year{y} / month{(unsigned)mo} / day{(unsigned)d};
  if (!ymd.ok())
    return false;

  int64_t midnight = sys_days(ymd).time_since_epoch().count() * 86400LL;
  lo = midnight + hh * 3600 + mm * 60 + ss;
  hi = hasTime ? lo : midnight + 86399;
  return true;
}

std::vector<PathStep> fakePath(size_t nodes, bool colored, uint32_t seed) {
  std::mt19937 rng(seed);
  std::vector<PathStep> path(nodes);
  for (size_t i = 0; i < nodes; i++) {
    path[i].label = std::to_string(i);
    path[i].red = colored && (rng() & 1);
    path[i].wentLeft = i > 0 && (rng() & 1);
  }
  return path;
}

std::string trimmed(const std::string &text) {
  auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
  auto first = std::find_if_not(text.begin(), text.end(), isSpace);
  auto last = std::find_if_not(text.rbegin(), text.rend(), isSpace).base();
  return first < last ? std::string(first, last) : std::string();
}

std::string formatDate(int64_t seconds) {
  using namespace std::chrono;
  return std::format("{:%F %T}", sys_seconds{std::chrono::seconds{seconds}});
}

static const char *severityName(Severity severity) {
  switch (severity) {
  case Severity::None:
    return "NONE";
  case Severity::Low:
    return "LOW";
  case Severity::Medium:
    return "MEDIUM";
  case Severity::High:
    return "HIGH";
  case Severity::Critical:
    return "CRITICAL";
  case Severity::Unknown:
    break;
  }
  return "UNKNOWN";
}

std::string buildCveText(const CveRecord &record) {
  std::string text = record.id + "\n\n";
  text += "Published:     " + formatDate(record.published) + "\n";
  text += "Last modified: " + formatDate(record.lastModified) + "\n";
  text += "Status:        " + record.status + "\n";
  if (record.cvss) {
    text += std::format("Severity:      {} ({:.1f})\n",
                        severityName(record.cvss->baseSeverity),
                        record.cvss->baseScore);
    text += "Vector:        " + record.cvss->vectorString + "\n";
  } else {
    text += "Severity:      no CVSS v4 score\n";
  }

  text += "\nDescription\n" + record.description + "\n";

  // some records list thousands, which would take forever to decrypt
  text += std::format("\nCPEs ({})\n", record.cpes.size());
  size_t shown = std::min(record.cpes.size(), CPE_LINES_MAX);
  for (size_t i = 0; i < shown; i++) {
    const Cpe &cpe = record.cpes[i];
    text += "  " + cpe.vendor + ":" + cpeKey(cpe) +
            (cpe.vulnerable ? " [vulnerable]\n" : "\n");
  }
  if (shown < record.cpes.size())
    text += std::format("  ... and {} more\n", record.cpes.size() - shown);
  return text;
}

HopState hopAt(double t, size_t hops) {
  size_t slow = std::min(hops, SLOW_HOPS);
  size_t fast = hops - slow;
  double fastTime = fast > 0 ? FAST_TIME : 0.0;

  if (t >= animationLength(hops))
    return {hops, 0.0, false, true, 0.0};

  double s;
  double left = 0.0;
  if (t < fastTime) {
    left = 1.0 - t / fastTime;
    s = fast * (1.0 - left * left);
  } else {
    s = fast + (t - fastTime) / SLOW_HOP_TIME;
  }
  size_t node = std::min((size_t)s, hops - 1);
  return {node, s - node, t < fastTime, false, left};
}

double animationLength(size_t hops) {
  size_t slow = std::min(hops, SLOW_HOPS);
  return (hops > slow ? FAST_TIME : 0.0) + slow * SLOW_HOP_TIME;
}
