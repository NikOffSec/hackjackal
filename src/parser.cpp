#include <parser.h>

std::string read_file(std::string filepath) {
  std::ifstream file(filepath);
  if (!file)
    throw std::runtime_error("can't open the file" + filepath);
  std::string data(std::filesystem::file_size(filepath), '\0');

  file.read(data.data(), data.size());
  return data;
}

// the whole file once it's read in, pos is where we're at in it
std::string json;
size_t pos = 0;

std::string parseString() {
  pos++; // skip the opening quote
  std::string str;

  while (pos < json.size() && json[pos] != '"') {
    char c = json[pos++];
    if (c != '\\') {
      str += c;
      continue;
    }

    // backslash at the very end, let the check below catch it
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
      // keep unicode as is for now, the 4 hex digits get copied next loop
      str += "\\u";
      break;
    default:
      // covers \" \\ and \/
      str += esc;
    }
  }

  if (pos >= json.size())
    throw std::runtime_error("string never got closed");

  pos++; // skip the closing quote
  return str;
}
