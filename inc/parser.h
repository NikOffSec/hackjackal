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

Value parseValue();

std::string read_file(std::string filepath);
std::string parseString();

void skipWhitespace();
char peek();

Object parseObject();
Array parseArray();
