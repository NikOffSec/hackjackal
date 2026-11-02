#include <filesystem>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

struct Value;
using Object = std::map<std::string, Value>;
using Array = std::vector<Value>;

struct Value {
  std::variant<std::nullptr_t, bool, double, std::string, Array, Object> data;
};

// these live in parser.cpp, declared here so tests and stuff can use them
extern std::string json;
extern size_t pos;

Value parseValue();

std::string read_file(std::string filepath);
std::string parseString();

void skipWhitespace();
char peek();

Object parseObject();
Array parseArray();

bool parseBool();
std::nullptr_t parseNull();
double parseNumber();
