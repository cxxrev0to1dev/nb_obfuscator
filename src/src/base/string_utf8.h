#ifndef BASE_STRING_UTF8_H_
#define BASE_STRING_UTF8_H_

#include <string>

namespace base {
  class StringUtf8 {
  public:
    explicit StringUtf8(const std::string& src);
    explicit StringUtf8(const std::wstring& src);
    virtual ~StringUtf8();
    const std::string GetDstA() const {
      return dst_a;
    }
    const std::wstring GetDstW() const {
      return dst_w;
    }
  private:
    void reset();
    std::wstring FromBytes(const std::string& src);
    std::string ToBytes(const std::wstring& src);
    std::string dst_a;
    std::wstring dst_w;
  };
}

#endif