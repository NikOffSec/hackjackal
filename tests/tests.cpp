#include <catch2/catch_test_macros.hpp>
#include <cve.h>
#include <filesystem>
#include <parser.h>
#include <random>
#include <redblack.h>
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
                     {"openssl", "openssl", "1.1", true}};
  records[1].published = 100;
  records[1].cpes = {{"linux", "linux_kernel", "-", false}};
  records[2].published = 300;
  records[2].cpes = {{"openssl", "openssl", "*", true}};

  RedBlackTree<std::string> byCpe;
  RedBlackTree<int64_t> byDate;
  buildRedBlackTrees(records, byCpe, byDate);

  // record 0 lists openssl twice but should only show up once
  REQUIRE(*byCpe.find("openssl:openssl") == std::vector<uint32_t>{0, 2});
  REQUIRE(*byCpe.find("linux:linux_kernel") == std::vector<uint32_t>{1});
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
  const std::vector<uint32_t> *hits = byCpe.find("openssl:openssl");
  REQUIRE(hits != nullptr);
  for (uint32_t i : *hits) {
    bool found = false;
    for (const Cpe &cpe : records[i].cpes)
      found = found || cpeKey(cpe) == "openssl:openssl";
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
