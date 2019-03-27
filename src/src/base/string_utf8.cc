#include "string_utf8.h"
#include <codecvt>

namespace base {
  StringUtf8::StringUtf8(const std::string& src) {
    reset();
    dst_w = FromBytes(src);
  }
  StringUtf8::StringUtf8(const std::wstring& src) {
    reset();
    dst_a = ToBytes(src);
  }
  void StringUtf8::reset() {
    dst_a.resize(0);
    dst_w.resize(0);
  }
  std::wstring StringUtf8::FromBytes(const std::string& src) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> cconv;
    return cconv.from_bytes(src);
  }
  std::string StringUtf8::ToBytes(const std::wstring& src) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> cconv;
    return cconv.to_bytes(src);
  }
  StringUtf8::~StringUtf8() {
    reset();
  }
}