#include <parser.h>

std::string read_file(std::string filepath) {
  std::ifstream file(filepath);
  if (!file)
    throw std::runtime_error("can't open the file" + filepath);
  std::string data(std::filesystem::file_size(filepath), '\0');

  file.read(data.data(), data.size());
  return data;
}

// whole file goes here, pos is where we're at
std::string json;
size_t pos = 0;

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
