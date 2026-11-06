#pragma once
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

// these live in parser.cpp, declared here so tests and stuff can use them.
// each thread gets its own so feeds can be parsed at the same time
extern thread_local std::string json;
extern thread_local size_t pos;

// when set, parseObject steps over any key this says yes to instead of storing
// it. nullptr keeps everything
extern thread_local bool (*skipField)(const std::string &key);

Value parseValue();
void skipValue();
Object parseObject();
Array parseArray();
std::string parseString();
bool parseBool();
std::nullptr_t parseNull();
double parseNumber();

std::string read_file(std::string filepath);

void skipWhitespace();
char peek();
