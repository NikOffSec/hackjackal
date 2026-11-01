#include <parser.h>
#include <stdexcept>

std::string json; // full file string
size_t pos = 0;   // index into string

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

std::string read_file(std::string filepath) {
  std::ifstream file(filepath);
  if (!file)
    throw std::runtime_error("can't open the file" + filepath);
  std::string data(std::filesystem::file_size(filepath), '\0');

  file.read(data.data(), data.size());
  return data;
}

std::string parseString() {
  pos++;
  std::string str;

  while (pos < json.size() && json[pos] != '"') {
    char c = json[pos++];
    if (c != '\\') {
      str += c;
      continue;
    }

    if (pos >= json.size())
      break;

    switch (char esc = json[pos++]) {
    case 'n':
      str += '\n';
      break;
    case 't':
      str += '\t';
      break;
    case 'r':
      str += '\r';
      break;
    case 'b':
      str += '\b';
      break;
    case 'f':
      str += '\f';
      break;
    case 'u':
      // TODO: actually decode unicode
      str += "\\u";
      break;
    default:
      // \" \\ and \/
      str += esc;
    }
  }

  if (pos >= json.size())
    throw std::runtime_error("string never got closed");

  pos++;
  return str;
}

void skipWhitespace() {
  while (pos < json.size()) {
    char c = json[pos];
    if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
      break;
    pos++;
  }
}

char peek() { return json[pos]; }

Object parseObject() {
  Object obj;
  pos++;
  skipWhitespace();

  if (pos < json.size() && json[pos] == '}') {
    pos++;
    return obj;
  }

  while (true) {
    skipWhitespace();
    if (pos >= json.size() || json[pos] != '"')
      throw std::runtime_error("expected key string");
    std::string key = parseString();

    skipWhitespace();
    if (pos >= json.size() || json[pos] != ':')
      throw std::runtime_error("expected ':'");
    pos++;

    obj[key] = parseValue();

    skipWhitespace();
    if (pos >= json.size())
      throw std::runtime_error("object never got closed");
    if (json[pos] == '}') {
      pos++;
      return obj;
    }
    if (json[pos] != ',')
      throw std::runtime_error("expected ',' or '}' but got neither");
    pos++;
  }
}

Array parseArray() {
  Array arr;
  pos++;
  skipWhitespace();

  if (pos < json.size() && json[pos] == ']') {
    pos++;
    return arr;
  }

  while (true) {
    arr.push_back(parseValue());

    skipWhitespace();
    if (pos >= json.size())
      throw std::runtime_error("array never got closed");
    if (json[pos] == ']') {
      pos++;
      return arr;
    }
    if (json[pos] != ',')
      throw std::runtime_error("expected ',' or ']'");
    pos++;
  }
}
