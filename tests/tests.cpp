#include <catch2/catch_test_macros.hpp>
#include <parser.h>

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
