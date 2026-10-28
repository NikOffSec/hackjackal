#include <filesystem>
#include <fstream>
#include <string>

std::string read_file(std::string filepath) {
  std::ifstream file(filepath);
  if (!file)
    throw std::runtime_error("can't open the file" + filepath);
  std::string data(std::filesystem::file_size(filepath), '\0');

  file.read(data.data(), data.size());
  return data;
}

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
