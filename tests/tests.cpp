#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <cve.h>
#include <filesystem>
#include <parser.h>
#include <random>
#include <redblack.h>
#include <search.h>
#include <splay.h>
#include <string>

// point the parser at a new string and start from the beginning
void load(std::string text) {
  json = text;
  pos = 0;
}

TEST_CASE("parseString reads a plain string") {
  load(R"("CVE-2024-1234")");
  REQUIRE(parseString() == "CVE-2024-1234");
}

TEST_CASE("parseString handles escapes") {
  load(R"("he said \"hi\"")");
  REQUIRE(parseString() == "he said \"hi\"");

  load(R"("a\nb\tc\\d\/e")");
  REQUIRE(parseString() == "a\nb\tc\\d/e");
}

TEST_CASE("parseString leaves unicode alone") {
  load("\"caf\\u00e9\"");
  REQUIRE(parseString() == "caf\\u00e9");
}

TEST_CASE("parseString stops right after the closing quote") {
  load(R"("first", "second")");
  REQUIRE(parseString() == "first");
  REQUIRE(json[pos] == ',');
}

TEST_CASE("parseString throws if the string never closes") {
  load(R"("no end)");
  REQUIRE_THROWS(parseString());

  load(R"("ends with \)");
  REQUIRE_THROWS(parseString());
}

TEST_CASE("parseBool reads true and false") {
  load("true");
  REQUIRE(parseBool() == true);

  load("false");
  REQUIRE(parseBool() == false);
}

TEST_CASE("parseBool throws on junk") {
  load("tru");
  REQUIRE_THROWS(parseBool());

  load("fals");
  REQUIRE_THROWS(parseBool());
}

TEST_CASE("parseNull reads null") {
  load("null");
  REQUIRE(parseNull() == nullptr);
  REQUIRE(pos == 4);

  load("nul");
  REQUIRE_THROWS(parseNull());
}

TEST_CASE("parseNumber reads all kinds of numbers") {
  load("42");
  REQUIRE(parseNumber() == 42);

  load("9.8");
  REQUIRE(parseNumber() == 9.8);

  load("-12.5e+1");
  REQUIRE(parseNumber() == -125);
}

TEST_CASE("parseNumber throws when there's no number") {
  load("@");
  REQUIRE_THROWS(parseNumber());
}

TEST_CASE("parseValue puts it all together") {
  load(R"({
    "id": "CVE-2024-1234",
    "vulnerable": true,
    "baseScore": 9.8,
    "cvss": null,
    "cpes": ["cpe:2.3:a:foo", "cpe:2.3:a:bar"]
  })");
  Value v = parseValue();
  auto &obj = std::get<Object>(v.data);

  REQUIRE(std::get<std::string>(obj["id"].data) == "CVE-2024-1234");
  REQUIRE(std::get<bool>(obj["vulnerable"].data) == true);
  REQUIRE(std::get<double>(obj["baseScore"].data) == 9.8);
  REQUIRE(std::holds_alternative<std::nullptr_t>(obj["cvss"].data));

  auto &cpes = std::get<Array>(obj["cpes"].data);
  REQUIRE(cpes.size() == 2);
  REQUIRE(std::get<std::string>(cpes[1].data) == "cpe:2.3:a:bar");
}

TEST_CASE("parseDate turns NVD dates into seconds") {
  REQUIRE(parseDate("1970-01-01T00:00:00.000") == 0);
  REQUIRE(parseDate("1970-01-02T01:00:05.000") == 86400 + 3600 + 5);
  REQUIRE(parseDate("1997-08-13T04:00:00.000") == 871444800);
  REQUIRE(parseDate("2026-10-09T19:16:39.027") >
          parseDate("2026-10-09T19:16:38.999"));
  REQUIRE(parseDate("junk") == 0);
}

TEST_CASE("parseCpe pulls out vendor, product and version") {
  Cpe cpe = parseCpe("cpe:2.3:a:commvault:commvault:11.20:*:*:*:*:*:*:*", true);
  REQUIRE(cpe.vendor == "commvault");
  REQUIRE(cpe.product == "commvault");
  REQUIRE(cpe.version == "11.20");
  REQUIRE(cpe.vulnerable);

  cpe = parseCpe(R"(cpe:2.3:a:foo\:bar:baz:1.0:*:*:*:*:*:*:*)", false);
  REQUIRE(cpe.vendor == "foo:bar");
  REQUIRE(cpe.product == "baz");
  REQUIRE_FALSE(cpe.vulnerable);
}

TEST_CASE("toRecord fills in a CveRecord") {
  load(R"({
    "id": "CVE-2024-1234",
    "published": "2024-01-02T03:04:05.000",
    "lastModified": "2024-02-02T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": [
      {"lang": "es", "value": "hola"},
      {"lang": "en", "value": "bad bug"}
    ],
    "metrics": {"cvssMetricV40": [{"cvssData": {
      "baseScore": 8.7, "baseSeverity": "HIGH", "attackVector": "NETWORK",
      "attackRequirements": "PRESENT", "userInteraction": "PASSIVE",
      "privilegesRequired": "LOW"
    }}]},
    "configurations": [{"nodes": [{"cpeMatch": [
      {"vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*"},
      {"vulnerable": false, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}
    ]}]}]
  })");
  Value v = parseValue();
  CveRecord rec = toRecord(std::get<Object>(v.data));

  REQUIRE(rec.id == "CVE-2024-1234");
  REQUIRE(rec.published == parseDate("2024-01-02T03:04:05.000"));
  REQUIRE(rec.status == "Analyzed");
  REQUIRE(rec.description == "bad bug");

  REQUIRE(rec.cpes.size() == 2);
  REQUIRE(rec.cpes[0].vendor == "acme");
  REQUIRE(rec.cpes[1].product == "linux_kernel");
  REQUIRE_FALSE(rec.cpes[1].vulnerable);

  REQUIRE(rec.cvss.has_value());
  REQUIRE(rec.cvss->baseScore == 8.7f);
  REQUIRE(rec.cvss->baseSeverity == Severity::High);
  REQUIRE(rec.cvss->attackVector == AttackVector::Network);
  REQUIRE(rec.cvss->attackRequirements == AttackRequirements::Present);
  REQUIRE(rec.cvss->userInteraction == UserInteraction::Passive);
  REQUIRE(rec.cvss->privilegesRequired == Level::Low);
  REQUIRE(rec.cvss->attackComplexity == Level::Unknown);
}

TEST_CASE("toRecord doesn't crash on a record missing stuff") {
  load(R"({"id": "CVE-2024-0001"})");
  Value v = parseValue();
  CveRecord rec = toRecord(std::get<Object>(v.data));
  REQUIRE(rec.id == "CVE-2024-0001");
  REQUIRE(rec.cpes.empty());
  REQUIRE_FALSE(rec.cvss.has_value());
}

TEST_CASE("loadRecords reads the real NVD file") {
  std::string path = std::string(DATA_DIR) + "/nvdcve-2.0-modified.json";
  if (!std::filesystem::exists(path))
    SKIP("no data file in data/");

  std::vector<CveRecord> records = loadRecords(path);
  REQUIRE(records.size() == 11628);
  REQUIRE(records[0].id == "CVE-1999-0024");
  REQUIRE(records[0].description ==
          "DNS cache poisoning via BIND, by predictable query IDs.");
}

TEST_CASE("buildRedBlackTrees sorts records by cpe and date") {
  std::vector<CveRecord> records(3);
  records[0].published = 300;
  records[0].cpes = {{"openssl", "openssl", "1.0", true},
                     {"openssl", "openssl", "1.0", false}};
  records[1].published = 100;
  records[1].cpes = {{"linux", "linux_kernel", "-", false}};
  records[2].published = 300;
  records[2].cpes = {{"openssl", "openssl", "1.0", true}};

  RedBlackTree<std::string> byCpe;
  RedBlackTree<int64_t> byDate;
  buildRedBlackTrees(records, byCpe, byDate);

  // record 0 lists openssl twice but should only show up once
  REQUIRE(*byCpe.find("openssl:1.0") == std::vector<uint32_t>{0, 2});
  REQUIRE(*byCpe.find("linux_kernel:-") == std::vector<uint32_t>{1});
  REQUIRE(*byDate.find(300) == std::vector<uint32_t>{0, 2});
  REQUIRE(*byDate.find(100) == std::vector<uint32_t>{1});
  REQUIRE(byCpe.size() == 2);
  REQUIRE(byDate.size() == 2);
}

TEST_CASE("buildRedBlackTrees works on the real NVD file") {
  std::string path = std::string(DATA_DIR) + "/nvdcve-2.0-modified.json";
  if (!std::filesystem::exists(path))
    SKIP("no data file in data/");

  std::vector<CveRecord> records = loadRecords(path);
  RedBlackTree<std::string> byCpe;
  RedBlackTree<int64_t> byDate;
  buildRedBlackTrees(records, byCpe, byDate);

  REQUIRE(byCpe.valid());
  REQUIRE(byDate.valid());

  // every cve in the openssl list should actually have an openssl cpe
  const std::vector<uint32_t> *hits = byCpe.find("openssl:*");
  REQUIRE(hits != nullptr);
  for (uint32_t i : *hits) {
    bool found = false;
    for (const Cpe &cpe : records[i].cpes)
      found = found || cpeKey(cpe) == "openssl:*";
    REQUIRE(found);
  }
}

TEST_CASE("red black tree insert and find") {
  RedBlackTree<std::string> tree;
  tree.insert("cpe:b", 0);
  tree.insert("cpe:a", 1);
  tree.insert("cpe:c", 2);

  REQUIRE(tree.size() == 3);
  REQUIRE(tree.find("cpe:a") != nullptr);
  REQUIRE((*tree.find("cpe:a"))[0] == 1);
  REQUIRE(tree.find("cpe:zzz") == nullptr);
  REQUIRE(tree.valid());
}

TEST_CASE("red black tree keeps duplicate keys in one node") {
  RedBlackTree<int64_t> tree;
  tree.insert(100, 0);
  tree.insert(100, 5);
  tree.insert(100, 9);

  REQUIRE(tree.size() == 1);
  REQUIRE(*tree.find(100) == std::vector<uint32_t>{0, 5, 9});
}

TEST_CASE("red black tree stays balanced with sorted inserts") {
  // sorted input is the worst case for a plain BST, it'd be height 10000
  RedBlackTree<int64_t> tree;
  for (int i = 0; i < 10000; i++)
    tree.insert(i, i);

  REQUIRE(tree.size() == 10000);
  REQUIRE(tree.valid());
  REQUIRE(tree.height() <= 28); // 2 * log2(10000)
}

TEST_CASE("red black tree stays valid with random inserts") {
  RedBlackTree<int64_t> tree;
  std::mt19937 rng(42);
  for (int i = 0; i < 5000; i++)
    tree.insert(rng() % 2000, i);

  REQUIRE(tree.valid());
  REQUIRE(tree.height() <= 22); // 2 * log2(2000)
}

TEST_CASE("red black tree inorder comes out sorted") {
  RedBlackTree<std::string> tree;
  for (std::string s : {"pear", "apple", "fig", "banana", "kiwi"})
    tree.insert(s, 0);

  std::vector<std::string> keys;
  tree.inorder([&](const std::string &key, const std::vector<uint32_t> &) {
    keys.push_back(key);
  });
  REQUIRE(keys ==
          std::vector<std::string>{"apple", "banana", "fig", "kiwi", "pear"});
}

TEST_CASE("red black tree range only gives keys in between") {
  RedBlackTree<int64_t> tree;
  for (int i = 0; i < 100; i++)
    tree.insert(i * 10, i);

  std::vector<int64_t> keys;
  tree.range(250, 300, [&](int64_t key, const std::vector<uint32_t> &) {
    keys.push_back(key);
  });
  REQUIRE(keys == std::vector<int64_t>{250, 260, 270, 280, 290, 300});
}

template <typename Tree> static void fillTraceTree(Tree &tree) {
  for (int key : {50, 25, 75, 10, 30, 60, 90})
    tree.insert(key, key);
}

TEST_CASE("tracePath ends on the key and starts at the root") {
  RedBlackTree<int64_t> tree;
  fillTraceTree(tree);

  std::vector<const RedBlackNode<int64_t> *> path;
  tree.tracePath(30, path);
  REQUIRE(!path.empty());
  REQUIRE(path.back()->key == 30);
  for (size_t i = 1; i < path.size(); i++)
    REQUIRE((path[i - 1]->left == path[i] || path[i - 1]->right == path[i]));
}

TEST_CASE("tracePath on a miss stops at the last node find would reach") {
  SplayTree<int64_t> tree;
  fillTraceTree(tree);
  tree.find(50);

  std::vector<const SplayNode<int64_t> *> path;
  tree.tracePath(33, path);
  REQUIRE(!path.empty());
  const SplayNode<int64_t> *last = path.back();
  REQUIRE((last->key < 33 ? last->right : last->left) == nullptr);

  // find leaves the closest node it reached at the root
  REQUIRE(tree.find(33) == nullptr);
  std::vector<const SplayNode<int64_t> *> after;
  tree.tracePath(33, after);
  REQUIRE(after.front()->key == last->key);
}

TEST_CASE("tracePath doesn't splay") {
  SplayTree<int64_t> tree;
  fillTraceTree(tree);

  std::vector<const SplayNode<int64_t> *> first, second;
  tree.tracePath(10, first);
  tree.tracePath(10, second);
  REQUIRE(first == second);
  REQUIRE(first.size() > 1);

  // find moves it to the root, so now the path is just that one node
  tree.find(10);
  std::vector<const SplayNode<int64_t> *> afterFind;
  tree.tracePath(10, afterFind);
  REQUIRE(afterFind.size() == 1);
}

static std::vector<CveRecord> searchRecords() {
  std::vector<CveRecord> records(3);
  records[0].id = "CVE-A";
  records[0].published = parseDate("2024-01-02T03:04:05.000");
  records[0].cpes = {{"openssl", "openssl", "1.0", true}};
  records[1].id = "CVE-B";
  records[1].published = parseDate("2024-01-02T20:00:00.000");
  records[1].cpes = {{"openssl", "openssl", "1.0", true}};
  records[2].id = "CVE-C";
  records[2].published = parseDate("2024-03-09T00:00:00.000");
  records[2].cpes = {{"linux", "linux_kernel", "-", false}};
  return records;
}

TEST_CASE("runSearch finds the same records in all 4 trees") {
  CveStore store;
  store.records = searchRecords();
  store.build();
  using Ids = std::vector<uint32_t>;

  for (TreeKind tree : {TreeKind::RedBlack, TreeKind::Splay}) {
    SearchResult r = runSearch(store, tree, KeyKind::Cpe, "openssl:1.0");
    REQUIRE(r.matches == Ids{0, 1});
    REQUIRE(!r.path.empty());
    REQUIRE(r.path.front().wentLeft == false);

    r = runSearch(store, tree, KeyKind::Date, "2024-01-02");
    REQUIRE(r.matches == Ids{0, 1});
    REQUIRE(!r.path.empty());

    r = runSearch(store, tree, KeyKind::Date, "2024-03-09T00:00:00");
    REQUIRE(r.matches == Ids{2});

    r = runSearch(store, tree, KeyKind::Date, "2024-01-02 03:04:06");
    REQUIRE(r.matches.empty());
    REQUIRE(!r.path.empty());

    r = runSearch(store, tree, KeyKind::Cpe, "nope:nope");
    REQUIRE(r.matches.empty());
    REQUIRE(!r.path.empty());
  }
  REQUIRE(store.splayCpe.valid());
  REQUIRE(store.splayDate.valid());
}

TEST_CASE("runSearch only colors red black paths") {
  CveStore store;
  store.records = searchRecords();
  store.build();

  bool anyRed = false;
  for (const char *key : {"2024-01-02", "2024-03-09"})
    for (const PathStep &step :
         runSearch(store, TreeKind::Splay, KeyKind::Date, key).path)
      anyRed = anyRed || step.red;
  REQUIRE_FALSE(anyRed);
}

TEST_CASE("runSearch on an empty tree gives an empty path") {
  CveStore store;
  SearchResult r = runSearch(store, TreeKind::Splay, KeyKind::Cpe, "a:b");
  REQUIRE(r.path.empty());
  REQUIRE(r.matches.empty());
}

TEST_CASE("parseDateQuery takes days and timestamps") {
  int64_t lo, hi;
  REQUIRE(parseDateQuery("2024-01-02", lo, hi));
  REQUIRE(lo == parseDate("2024-01-02T00:00:00.000"));
  REQUIRE(hi == parseDate("2024-01-02T23:59:59.000"));

  REQUIRE(parseDateQuery("2024-01-02T03:04:05", lo, hi));
  REQUIRE(lo == hi);
  REQUIRE(lo == parseDate("2024-01-02T03:04:05.000"));

  for (const char *bad : {"", "junk", "2024-13-01", "2024-02-30", "2024/01/02",
                          "2024-01-02T25:00:00", "2024-01-02T03:04"})
    REQUIRE_FALSE(parseDateQuery(bad, lo, hi));
}

TEST_CASE("formatDate is the inverse of parseDate") {
  REQUIRE(formatDate(parseDate("1997-08-13T04:00:00.000")) ==
          "1997-08-13 04:00:00");
}

TEST_CASE("buildCveText limits how many cpes it lists") {
  CveRecord record;
  record.id = "CVE-X";
  record.cpes.assign(120, Cpe{"acme", "widget", "1", true});
  std::string text = buildCveText(record);
  REQUIRE(text.find("CVE-X") == 0);
  REQUIRE(text.find("CPEs (120)") != std::string::npos);
  REQUIRE(text.find("... and 70 more") != std::string::npos);
  REQUIRE(text.find("no CVSS v4 score") != std::string::npos);
}

TEST_CASE("hopAt takes the same time for any path length") {
  REQUIRE(animationLength(19) == animationLength(299999));
  REQUIRE(animationLength(19) < 5.0);

  for (size_t hops : {size_t(19), size_t(299999)}) {
    REQUIRE(hopAt(0.0, hops).node == 0);
    REQUIRE(hopAt(0.0, hops).fast);
    REQUIRE(hopAt(3.0, hops).node == hops - 3);
    REQUIRE_FALSE(hopAt(3.0, hops).fast);
    REQUIRE(hopAt(3.6, hops).node == hops - 2);
    REQUIRE(hopAt(4.2, hops).node == hops - 1);
    REQUIRE_FALSE(hopAt(4.7, hops).done);
    REQUIRE(hopAt(4.8, hops).done);
    REQUIRE(hopAt(4.8, hops).node == hops);

    // the head should only ever move forward
    double prev = 0.0;
    for (double t = 0.0; t < 4.8; t += 1.0 / 60.0) {
      HopState h = hopAt(t, hops);
      double s = (double)h.node + h.phase;
      REQUIRE(s >= prev);
      prev = s;
    }
  }
}

TEST_CASE("hopAt handles paths too short for a fast phase") {
  REQUIRE(hopAt(0.0, 0).done);
  REQUIRE(animationLength(2) == 2 * 0.6);
  REQUIRE_FALSE(hopAt(0.0, 2).fast);
  REQUIRE(hopAt(0.7, 2).node == 1);
  REQUIRE(hopAt(1.2, 2).done);
}

TEST_CASE("fakePath makes a path of the right length") {
  std::vector<PathStep> path = fakePath(300000, false, 1);
  REQUIRE(path.size() == 300000);
  REQUIRE(path.front().wentLeft == false);
  bool left = false, right = false;
  for (size_t i = 1; i < path.size(); i++)
    (path[i].wentLeft ? left : right) = true;
  REQUIRE(left);
  REQUIRE(right);
}

TEST_CASE("all 4 trees find every record in the real NVD file") {
  std::string path = std::string(DATA_DIR) + "/nvdcve-2.0-modified.json";
  if (!std::filesystem::exists(path))
    SKIP("no data file in data/");

  CveStore store;
  store.records = loadRecords(path);
  store.build();
  REQUIRE(store.rbDate.valid());
  REQUIRE(store.splayDate.valid());
  REQUIRE(store.rbCpe.valid());
  REQUIRE(store.splayCpe.valid());

  auto has = [](const std::vector<uint32_t> *hits, uint32_t record) {
    return hits && std::find(hits->begin(), hits->end(), record) != hits->end();
  };
  bool allFound = true;
  for (uint32_t i = 0; i < store.records.size(); i++) {
    const CveRecord &record = store.records[i];
    allFound = allFound && has(store.rbDate.find(record.published), i) &&
               has(store.splayDate.find(record.published), i);
    for (const Cpe &cpe : record.cpes)
      allFound = allFound && has(store.rbCpe.find(cpeKey(cpe)), i) &&
                 has(store.splayCpe.find(cpeKey(cpe)), i);
  }
  REQUIRE(allFound);
}

TEST_CASE("loadYearFeeds joins the yearly feeds and skips the rest") {
  namespace fs = std::filesystem;
  fs::path dir = fs::temp_directory_path() / "hackjackal_year_feeds";
  fs::create_directories(dir);
  auto write = [&](const char *name, const char *id) {
    std::ofstream(dir / name)
        << R"({"vulnerabilities": [{"cve": {"id": ")" << id << R"("}}]})";
  };
  write("nvdcve-2.0-2003.json", "CVE-B");
  write("nvdcve-2.0-2002.json", "CVE-A");
  write("nvdcve-2.0-modified.json", "CVE-DUPLICATE");
  write("nvdcve-2.0-recent.json", "CVE-DUPLICATE");
  std::ofstream(dir / "nvdcve-2.0-2004.json")
      << R"({"vulnerabilities": [{"cve": {"id": "CVE-GONE",
            "vulnStatus": "Rejected"}}]})";

  std::vector<CveRecord> records = loadYearFeeds(dir.string());
  fs::remove_all(dir);
  REQUIRE(records.size() == 2);
  REQUIRE(records[0].id == "CVE-A");
  REQUIRE(records[1].id == "CVE-B");
  REQUIRE_THROWS(loadYearFeeds(dir.string()));
}

TEST_CASE("loadYearFeeds keeps feeds in order and reports every one") {
  namespace fs = std::filesystem;
  fs::path dir = fs::temp_directory_path() / "hackjackal_many_feeds";
  fs::create_directories(dir);
  for (int year = 2000; year < 2020; year++)
    std::ofstream(dir / ("nvdcve-2.0-" + std::to_string(year) + ".json"))
        << R"({"version": "2.0", "vulnerabilities": [{"cve": {"id": ")" << year
        << R"("}}], "format": "NVD_CVE"})";

  // this runs on the worker threads and catch asserts aren't thread safe
  size_t calls = 0, lastDone = 0, lastTotal = 0;
  std::vector<CveRecord> records =
      loadYearFeeds(dir.string(), [&](size_t done, size_t total) {
        calls++;
        lastDone = done;
        lastTotal = total;
      });
  fs::remove_all(dir);
  REQUIRE(calls == 21);
  REQUIRE(lastDone == 20);
  REQUIRE(lastTotal == 20);
  REQUIRE(records.size() == 20);
  for (int i = 0; i < 20; i++)
    REQUIRE(records[i].id == std::to_string(2000 + i));
}

TEST_CASE("loadYearFeeds throws when any feed is broken") {
  namespace fs = std::filesystem;
  fs::path dir = fs::temp_directory_path() / "hackjackal_broken_feed";
  fs::create_directories(dir);
  std::ofstream(dir / "nvdcve-2.0-2002.json")
      << R"({"vulnerabilities": [{"cve": {"id": "CVE-A"}}]})";
  std::ofstream(dir / "nvdcve-2.0-2003.json")
      << R"({"vulnerabilities": [{"cve": {"id": "CVE-B"}})";

  REQUIRE_THROWS(loadYearFeeds(dir.string()));
  fs::remove_all(dir);
}

TEST_CASE("skipValue steps over any kind of value") {
  auto skipped = [](const std::string &text) {
    json = text;
    pos = 0;
    skipValue();
    return json.substr(pos);
  };

  REQUIRE(skipped("12.5,x") == ",x");
  REQUIRE(skipped("true}") == "}");
  REQUIRE(skipped(R"("text",x)") == ",x");
  REQUIRE(skipped(R"(  {"a": [1, {"b": 2}]},x)") == ",x");
  REQUIRE(skipped(R"(["]", "}", "\"]"],x)") == ",x");
  REQUIRE(skipped(R"("back\\",x)") == ",x");
}

TEST_CASE("skipValue throws on values that never end") {
  auto skip = [](const std::string &text) {
    json = text;
    pos = 0;
    skipValue();
  };

  REQUIRE_THROWS(skip(R"({"a": [1, 2])"));
  REQUIRE_THROWS(skip(R"("never closed)"));
  REQUIRE_THROWS(skip(R"("ends on escape\)"));
  REQUIRE_THROWS(skip(R"(["never closed])"));
  REQUIRE_THROWS(skip("}"));
  REQUIRE_THROWS(skip(""));
}

TEST_CASE("parseObject only skips fields when asked to") {
  auto parse = [] {
    json = R"({"keep": 1, "drop": [1, 2], "last": 3})";
    pos = 0;
    return parseObject();
  };
  REQUIRE(parse().size() == 3);

  skipField = [](const std::string &key) { return key == "drop"; };
  Object obj = parse();
  skipField = nullptr;
  REQUIRE(obj.size() == 2);
  REQUIRE(obj.count("keep") == 1);
  REQUIRE(obj.count("last") == 1);
  REQUIRE(pos == json.size());
}

TEST_CASE("loadRecords gets past unused fields and keeps the rest") {
  namespace fs = std::filesystem;
  fs::path path = fs::temp_directory_path() / "hackjackal_unused.json";
  std::ofstream(path) << R"({"vulnerabilities": [{"cve": {
    "id": "CVE-A",
    "references": [{"url": "http://x/]}\"", "tags": ["a"]}],
    "affected": [{"affectedData": [{"versions": [{"version": "1"}]}]}],
    "configurations": [{"nodes": [{"cpeMatch": [{
      "matchCriteriaId": "ABC", "vulnerable": true,
      "criteria": "cpe:2.3:a:vendor:product:1.0:*"}]}]}],
    "metrics": {
      "cvssMetricV31": [{"cvssData": {"baseScore": 1.0}}],
      "cvssMetricV40": [{"cvssData": {"baseScore": 9.5}}]},
    "weaknesses": []}},
    {"cve": {"id": "CVE-B"}}]})";

  std::vector<CveRecord> records = loadRecords(path.string());
  fs::remove(path);
  REQUIRE(records.size() == 2);
  REQUIRE(records[0].id == "CVE-A");
  REQUIRE(records[0].cpes.size() == 1);
  REQUIRE(records[0].cpes[0].product == "product");
  REQUIRE(records[0].cvss->baseScore == 9.5f);
  REQUIRE(records[1].id == "CVE-B");
}

TEST_CASE("loadRecords stops skipping fields even when it throws") {
  namespace fs = std::filesystem;
  fs::path path = fs::temp_directory_path() / "hackjackal_skip_throw.json";
  std::ofstream(path) << R"({"vulnerabilities": [{"cve": {"references": [)";
  REQUIRE_THROWS(loadRecords(path.string()));
  fs::remove(path);
  REQUIRE(skipField == nullptr);
}

TEST_CASE("loadRecords rejects malformed feeds") {
  namespace fs = std::filesystem;
  fs::path path = fs::temp_directory_path() / "hackjackal_malformed.json";
  auto load = [&](const char *text) {
    std::ofstream(path) << text;
    return loadRecords(path.string());
  };

  REQUIRE(load("{}").empty());
  REQUIRE(load(R"({"vulnerabilities": []})").empty());
  REQUIRE(load(R"({"vulnerabilities": [{"cve": {"id": "A"}}]})").size() == 1);
  REQUIRE_THROWS(load("[]"));
  REQUIRE_THROWS(load(""));
  REQUIRE_THROWS(load(R"({"version": "2.0",})"));
  REQUIRE_THROWS(load(R"({"vulnerabilities": [])"));
  REQUIRE_THROWS(load(R"({"vulnerabilities": [{"cve": {}})"));
  fs::remove(path);
}
