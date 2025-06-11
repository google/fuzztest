#ifndef FUZZTEST_INTERNAL_DOMAINS_XML_DOMAIN_H_
#define FUZZTEST_INTERNAL_DOMAINS_XML_DOMAIN_H_

#include <string>
#include <vector>

#include "fuzztest/internal/domains/domain_base.h"
#include "fuzztest/internal/domains/string_domains.h" // For StringOf, CharacterSet
#include "fuzztest/internal/domains/container_of_impl.h" // For VectorOf
#include "fuzztest/internal/domains/map_impl.h" // For Map
#include "fuzztest/internal/domains/one_of_impl.h" // For OneOf
#include "fuzztest/internal/domains/domain_builder.h" // For DomainBuilder
#include "fuzztest/internal/meta.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"


namespace fuzztest::internal {

// Forward declaration for recursive definition
class XmlElement;

// Domain for XML tag names (alphanumeric, starting with a letter)
inline auto XmlTagName() {
  return StringOf(AlphaNumericChar()).WithMinSize(1).Filter([](const std::string& s) {
    return !s.empty() && std::isalpha(s[0]);
  });
}

// Domain for XML attribute names (alphanumeric, starting with a letter)
inline auto XmlAttributeName() {
  return StringOf(AlphaNumericChar()).WithMinSize(1).Filter([](const std::string& s) {
    return !s.empty() && std::isalpha(s[0]);
  });
}

// Domain for XML attribute values (printable ASCII characters, excluding quotes)
inline auto XmlAttributeValue() {
  return StringOf(CharacterSet(" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+,-./:;<=>?@[]^_`{|}~"));
}

// Domain for XML attributes (a map of name-value pairs)
inline auto XmlAttributes() {
  return Map(
      [](auto&&... args) {
        return std::map<std::string, std::string>(std::forward<decltype(args)>(args)...);
      },
      VectorOf(PairOf(XmlAttributeName(), XmlAttributeValue())).WithMaxSize(5));
}


// Domain for XML content (text or nested elements)
// This will be part of the recursive definition using DomainBuilder
// For now, a simple text content domain.
inline auto XmlTextContent() {
    return StringOf(PrintableAsciiChar());
}


// Main XML Element Domain
inline auto XmlElementDomain() {
  DomainBuilder<XmlElement> builder;

  // Define the domain for the content of an XML element.
  // It can be either a simple text string or a vector of child XmlElement objects.
  // MaxDepth is used for the recursive part to prevent infinite recursion.
  // MaxElements for the container size.
  auto xml_content_variant_domain = OneOf(
      XmlTextContent().Map([](std::string s) { return XmlContentType(std::move(s)); }),
      builder.RecursiveContainerOf<std::vector>(/*max_depth=*/3, /*max_elements=*/5)
          .Map([](std::vector<XmlElement> v) { return XmlContentType(std::move(v)); })
  );

  builder.Set(
      XmlTagName(),                // domain for tag_name
      XmlAttributes(),             // domain for attributes
      xml_content_variant_domain   // domain for content (XmlContentType)
  );
  // The DomainBuilder by default uses fuzztest::Arbitrary<XmlElement> which requires
  // the type to be default constructible and aggregate initializable.
  // Since we have a custom constructor and want to use specific domains for fields,
  // we provide a factory function.
  // builder.Set relies on the order of arguments matching the constructor of XmlElement,
  // or matching the order of fields if it were an aggregate.

  return builder.Build().Map([](XmlElement&& element) {
    // Use the ToString() method of XmlElement for serialization.
    return element.ToString();
  });
}

#include <variant> // Required for std::variant

// Forward declaration
class XmlElement;

// Define content type: can be a string (text) or a vector of child XmlElements
using XmlContentType = std::variant<std::string, std::vector<XmlElement>>;

// Represents an XML element.
class XmlElement {
 public:
  std::string tag_name;
  std::map<std::string, std::string> attributes;
  XmlContentType content;

  XmlElement() = default;
  XmlElement(std::string tag, std::map<std::string, std::string> attrs, XmlContentType cont)
      : tag_name(std::move(tag)), attributes(std::move(attrs)), content(std::move(cont)) {}

  // Function to serialize the XmlElement to a string
  std::string ToString() const {
    std::string attrs_str;
    for (const auto& attr : attributes) {
      attrs_str += absl::StrCat(" ", attr.first, "=\"", attr.second, "\"");
    }

    std::string content_str;
    if (std::holds_alternative<std::string>(content)) {
      content_str = std::get<std::string>(content);
    } else if (std::holds_alternative<std::vector<XmlElement>>(content)) {
      for (const auto& child : std::get<std::vector<XmlElement>>(content)) {
        content_str += child.ToString();
      }
    }
    return absl::StrCat("<", tag_name, attrs_str, ">", content_str, "</", tag_name, ">");
  }

  template <typename Sink>
  friend void AbslStringify(Sink& sink, const XmlElement& element) {
    std::string attrs_str_repr;
    for (const auto& attr : element.attributes) {
      if (!attrs_str_repr.empty()) attrs_str_repr += ", ";
      attrs_str_repr += absl::StrCat(attr.first, "=", attr.second);
    }

    std::string content_repr;
    if (std::holds_alternative<std::string>(element.content)) {
      content_repr = absl::StrCat("\"", std::get<std::string>(element.content), "\"");
    } else if (std::holds_alternative<std::vector<XmlElement>>(element.content)) {
      content_repr = absl::StrCat("[", absl::StrJoin(std::get<std::vector<XmlElement>>(element.content), ", ", [](std::string* out, const XmlElement& e){ out->append(e.ToString()); }), "]");
    }

    absl::Format(&sink, "XmlElement{tag_name=%s, attributes={%s}, content=%s}",
                 element.tag_name, attrs_str_repr, content_repr);
  }
};


}  // namespace fuzztest::internal

#endif  // FUZZTEST_INTERNAL_DOMAINS_XML_DOMAIN_H_
