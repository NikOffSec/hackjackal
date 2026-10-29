#include <cstdint>
#include <optional>
#include <string>
#include <vector>

enum class Severity : uint8_t { None, Low, Medium, High, Critical, Unknown };
enum class AttackVector : uint8_t {
  Network,
  Adjacent,
  Local,
  Physical,
  Unknown
};
enum class Level : uint8_t { None, Low, High, Unknown };
enum class AttackRequirements : uint8_t { None, Present, Unknown };
enum class UserInteraction : uint8_t { None, Passive, Active, Unknown };

struct Cpe {
  std::string vendor;
  std::string product;
  std::string version;
  bool vulnerable;
};

struct CvssV4 {
  std::string vectorString;
  float baseScore;
  Severity baseSeverity;

  AttackVector attackVector;
  Level attackComplexity;
  AttackRequirements attackRequirements;
  Level privilegesRequired;
  UserInteraction userInteraction;

  Level vulnConfidentialityImpact;
  Level vulnIntegrityImpact;
  Level vulnAvailabilityImpact;
  Level subConfidentialityImpact;
  Level subIntegrityImpact;
  Level subAvailabilityImpact;
};

// plan is to build a vector of CveRecord objects here, then we can make two
// different Splay Trees and two different RedBlack trees, one is sorted by CPE
// key and one is sorted by date. The CPE key is the stuff at the bottom of each
// record, you can google the format
struct CveRecord {
  std::string id;
  int64_t published;
  int64_t lastModified;
  std::string description;
  std::string status;
  std::vector<Cpe> cpes;
  std::optional<CvssV4> cvss;
};
