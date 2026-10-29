#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

std::string read_file(std::string filepath);
std::string parseString();

Value parseValue() {
  skipWhitespace();
  switch (peek()) {
  case '{':
    return parseObject();
  case '[':
    return parseArray();
  case '"':
    return parseString();
  case 't':
  case 'f':
    return parseBool();
  case 'n':
    return parseNull();
  default:
    return parseNumber();
  }
}
