#include <algorithm>
#include <chrono>
#include <cve.h>
#include <iterator>
#include <string_view>

// grabs obj[key] if it's there and the right type, otherwise hands back an
// empty one so a weird record doesn't crash everything
template <typename T>
static const T &field(const Object &obj, const std::string &key) {
  static const T empty{};
  auto it = obj.find(key);
  if (it == obj.end())
    return empty;
  const T *val = std::get_if<T>(&it->second.data);
  return val ? *val : empty;
}

static const Object *asObject(const Value &v) {
  return std::get_if<Object>(&v.data);
}

static Severity toSeverity(const std::string &s) {
  if (s == "NONE")
    return Severity::None;
  if (s == "LOW")
    return Severity::Low;
  if (s == "MEDIUM")
    return Severity::Medium;
  if (s == "HIGH")
    return Severity::High;
  if (s == "CRITICAL")
    return Severity::Critical;
  return Severity::Unknown;
}

static AttackVector toAttackVector(const std::string &s) {
  if (s == "NETWORK")
    return AttackVector::Network;
  if (s == "ADJACENT")
    return AttackVector::Adjacent;
  if (s == "LOCAL")
    return AttackVector::Local;
  if (s == "PHYSICAL")
    return AttackVector::Physical;
  return AttackVector::Unknown;
}

static Level toLevel(const std::string &s) {
  if (s == "NONE")
    return Level::None;
  if (s == "LOW")
    return Level::Low;
  if (s == "HIGH")
    return Level::High;
  return Level::Unknown;
}

static AttackRequirements toAttackRequirements(const std::string &s) {
  if (s == "NONE")
    return AttackRequirements::None;
  if (s == "PRESENT")
    return AttackRequirements::Present;
  return AttackRequirements::Unknown;
}

static UserInteraction toUserInteraction(const std::string &s) {
  if (s == "NONE")
    return UserInteraction::None;
  if (s == "PASSIVE")
    return UserInteraction::Passive;
  if (s == "ACTIVE")
    return UserInteraction::Active;
  return UserInteraction::Unknown;
}

static CvssV4 toCvss(const Object &data) {
  CvssV4 cvss{};
  cvss.vectorString = field<std::string>(data, "vectorString");
  cvss.baseScore = (float)field<double>(data, "baseScore");
  cvss.baseSeverity = toSeverity(field<std::string>(data, "baseSeverity"));

  cvss.attackVector = toAttackVector(field<std::string>(data, "attackVector"));
  cvss.attackComplexity = toLevel(field<std::string>(data, "attackComplexity"));
  cvss.attackRequirements =
      toAttackRequirements(field<std::string>(data, "attackRequirements"));
  cvss.privilegesRequired =
      toLevel(field<std::string>(data, "privilegesRequired"));
  cvss.userInteraction =
      toUserInteraction(field<std::string>(data, "userInteraction"));

  cvss.vulnConfidentialityImpact =
      toLevel(field<std::string>(data, "vulnConfidentialityImpact"));
  cvss.vulnIntegrityImpact =
      toLevel(field<std::string>(data, "vulnIntegrityImpact"));
  cvss.vulnAvailabilityImpact =
      toLevel(field<std::string>(data, "vulnAvailabilityImpact"));
  cvss.subConfidentialityImpact =
      toLevel(field<std::string>(data, "subConfidentialityImpact"));
  cvss.subIntegrityImpact =
      toLevel(field<std::string>(data, "subIntegrityImpact"));
  cvss.subAvailabilityImpact =
      toLevel(field<std::string>(data, "subAvailabilityImpact"));
  return cvss;
}

// dates look like 1997-08-13T04:00:00.000, the milliseconds get dropped
int64_t parseDate(const std::string &date) {
  if (date.size() < 19)
    return 0;
  int y = std::stoi(date.substr(0, 4));
  unsigned m = std::stoi(date.substr(5, 2));
  unsigned d = std::stoi(date.substr(8, 2));
  int hh = std::stoi(date.substr(11, 2));
  int mm = std::stoi(date.substr(14, 2));
  int ss = std::stoi(date.substr(17, 2));

  using namespace std::chrono;
  sys_days ymd = year{y} / month{m} / day{d};
  return ymd.time_since_epoch().count() * 86400LL + hh * 3600 + mm * 60 + ss;
}

// cpe:2.3:part:vendor:product:version:... split on ':' but a few vendors
// have \: in their names so those don't count
Cpe parseCpe(const std::string &criteria, bool vulnerable) {
  std::vector<std::string> parts(1);
  for (size_t i = 0; i < criteria.size(); i++) {
    if (criteria[i] == '\\' && i + 1 < criteria.size())
      parts.back() += criteria[++i];
    else if (criteria[i] == ':')
      parts.emplace_back();
    else
      parts.back() += criteria[i];
  }

  Cpe cpe{};
  cpe.vulnerable = vulnerable;
  if (parts.size() > 5) {
    cpe.vendor = parts[3];
    cpe.product = parts[4];
    cpe.version = parts[5];
  }
  return cpe;
}

CveRecord toRecord(const Object &cve) {
  CveRecord rec{};
  rec.id = field<std::string>(cve, "id");
  rec.published = parseDate(field<std::string>(cve, "published"));
  rec.lastModified = parseDate(field<std::string>(cve, "lastModified"));
  rec.status = field<std::string>(cve, "vulnStatus");

  for (const Value &v : field<Array>(cve, "descriptions")) {
    const Object *desc = asObject(v);
    if (desc && field<std::string>(*desc, "lang") == "en") {
      rec.description = field<std::string>(*desc, "value");
      break;
    }
  }

  // cpes are buried in configurations -> nodes -> cpeMatch
  for (const Value &c : field<Array>(cve, "configurations")) {
    const Object *config = asObject(c);
    if (!config)
      continue;
    for (const Value &n : field<Array>(*config, "nodes")) {
      const Object *node = asObject(n);
      if (!node)
        continue;
      for (const Value &m : field<Array>(*node, "cpeMatch")) {
        const Object *match = asObject(m);
        if (match)
          rec.cpes.push_back(parseCpe(field<std::string>(*match, "criteria"),
                                      field<bool>(*match, "vulnerable")));
      }
    }
  }

  // only some records have a v4 score, the rest stay empty
  const Object &metrics = field<Object>(cve, "metrics");
  const Array &v4 = field<Array>(metrics, "cvssMetricV40");
  if (!v4.empty())
    if (const Object *metric = asObject(v4[0]))
      rec.cvss = toCvss(field<Object>(*metric, "cvssData"));

  return rec;
}

// big fields in the feeds that toRecord never reads, about half of each entry.
// if toRecord starts using one of these it has to come off this list or it'll
// just show up empty
static bool isUnusedField(const std::string &key) {
  static constexpr std::string_view unused[] = {
      "affected",        "references",       "weaknesses",
      "cvssMetricV2",    "cvssMetricV30",    "cvssMetricV31",
      "ssvcV203",        "matchCriteriaId",  "sourceIdentifier"};
  return std::find(std::begin(unused), std::end(unused), key) !=
         std::end(unused);
}

// keeps skipField from staying on for whoever parses next if loading throws
struct SkipUnusedFields {
  SkipUnusedFields() { skipField = isUnusedField; }
  ~SkipUnusedFields() { skipField = nullptr; }
};

// turns each entry into a record as soon as it's parsed, holding the whole feed
// as Values takes about 4x its size in memory
static void parseVulnerabilities(std::vector<CveRecord> &records) {
  pos++;
  skipWhitespace();
  if (pos < json.size() && json[pos] == ']') {
    pos++;
    return;
  }

  while (true) {
    Value v = parseValue();
    if (const Object *entry = asObject(v))
      records.push_back(toRecord(field<Object>(*entry, "cve")));

    skipWhitespace();
    if (pos >= json.size())
      throw std::runtime_error("array never got closed");
    if (json[pos] == ']') {
      pos++;
      return;
    }
    if (json[pos] != ',')
      throw std::runtime_error("expected ',' or ']'");
    pos++;
  }
}

std::vector<CveRecord> loadRecords(std::string filepath) {
  json = read_file(filepath);
  pos = 0;
  SkipUnusedFields skipping;
  std::vector<CveRecord> records;

  skipWhitespace();
  if (pos >= json.size() || json[pos] != '{')
    throw std::runtime_error("expected the json to start with an object");
  pos++;
  skipWhitespace();

  bool closed = pos < json.size() && json[pos] == '}';
  while (!closed) {
    skipWhitespace();
    if (pos >= json.size() || json[pos] != '"')
      throw std::runtime_error("expected key string");
    std::string key = parseString();

    skipWhitespace();
    if (pos >= json.size() || json[pos] != ':')
      throw std::runtime_error("expected ':'");
    pos++;

    skipWhitespace();
    if (key == "vulnerabilities" && pos < json.size() && json[pos] == '[')
      parseVulnerabilities(records);
    else
      parseValue();

    skipWhitespace();
    if (pos >= json.size())
      throw std::runtime_error("object never got closed");
    closed = json[pos] == '}';
    if (!closed && json[pos] != ',')
      throw std::runtime_error("expected ',' or '}' but got neither");
    pos++;
  }

  // done with the raw text, free it up since the file is big
  json.clear();
  json.shrink_to_fit();
  return records;
}

std::string cpeKey(const Cpe &cpe) { return cpe.product + ":" + cpe.version; }
