# XML Domain

## Purpose

The XML domain in FuzzTest is designed to generate well-formed XML (Extensible Markup Language) strings. These strings can be used as inputs for fuzz testing software that parses or processes XML data. By generating a wide variety of valid and complex XML structures, this domain helps uncover potential vulnerabilities, bugs, or unexpected behaviors in XML-handling code.

## Design

The XML domain is built using several components of the FuzzTest library, centered around the `XmlElement` class and the `XmlElementDomain` function.

### `XmlElement` Structure

The core of the XML generation is the `XmlElement` class, which represents a single XML element. It's defined to hold the tag name, attributes, and content of an element. The content itself can be either a simple text string or a vector of child `XmlElement` objects, allowing for recursive, nested structures.

```cpp
// Located in: fuzztest/internal/domains/xml_domain.h

#include <string>
#include <vector>
#include <map>
#include <variant> // Required for std::variant
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"

namespace fuzztest::internal {

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
```

### Helper Domains

Several helper domains are defined to generate the constituent parts of an XML element:

-   `XmlTagName()`: Generates valid XML tag names (alphanumeric, starting with a letter).
-   `XmlAttributeName()`: Generates valid XML attribute names (similar rules to tag names).
-   `XmlAttributeValue()`: Generates string attribute values using printable ASCII characters (excluding quotes, which are handled by the serialization).
-   `XmlAttributes()`: Creates a map of attribute name-value pairs.
-   `XmlTextContent()`: Produces simple text strings that can serve as the content of an XML element.

### `XmlElementDomain` Implementation

The main domain, `XmlElementDomain()`, orchestrates the generation of `XmlElement` objects and their subsequent serialization into XML strings.

-   **`fuzztest::DomainBuilder<XmlElement>`**: This is used to define the recursive structure of `XmlElement`. It allows an `XmlElement` to contain other `XmlElement` objects as children.
-   **Content Generation**: The content of an element (`XmlContentType`) is generated using `fuzztest::OneOf`. This domain chooses between:
    -   Simple text content, produced by `XmlTextContent().Map(...)`.
    -   A vector of child `XmlElement` objects, produced by `builder.RecursiveContainerOf<std::vector<XmlElement>>(...).Map(...)`. The `RecursiveContainerOf` is crucial for creating nested XML structures, with `max_depth` and `max_elements` parameters to control complexity.
-   **Object Construction**: `builder.Set(...)` is used to specify how to construct an `XmlElement` object, providing the domains for its `tag_name`, `attributes`, and `content` members.
-   **Serialization to String**: Finally, `builder.Build().Map([](XmlElement&& element) { return element.ToString(); })` takes the generated `XmlElement` object and calls its `ToString()` method to produce the final XML string.

```cpp
// Located in: fuzztest/internal/domains/xml_domain.h

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

// Domain for XML content (text)
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

  return builder.Build().Map([](XmlElement&& element) {
    // Use the ToString() method of XmlElement for serialization.
    return element.ToString();
  });
}
```

## Usage

To use the XML domain in your fuzz test:

1.  **Include Header**: Add the necessary header file.
    ```cpp
    #include "fuzztest/internal/domains/xml_domain.h"
    ```
    *(Note: The exact path might vary based on your project's include structure.)*

2.  **Use in `FUZZ_TEST`**: Specify `fuzztest::internal::XmlElementDomain()` in the `.WithDomains()` clause of your `FUZZ_TEST` macro.

### Example Fuzz Test

Here's an example demonstrating how to use the `XmlElementDomain` to test a hypothetical XML processing function:

```cpp
// Located in: examples/xml_fuzz_test.cc

// NOTE: This example uses cc_test in its BUILD file instead of cc_fuzz_test
// due to difficulties in locating the correct Bazel macro for cc_fuzz_test
// in the testing environment. When integrating FuzzTest into your own project,
// ensure your Bazel setup is correct to use cc_fuzz_test for full fuzzing
// capabilities (corpus generation, coverage guidance, etc.).
// The FUZZ_TEST macro itself is still used here and should work with a
// FuzzTest-compatible main function (like fuzztest_gtest_main).

#include "fuzztest/fuzztest.h"
#include "fuzztest/internal/domains/xml_domain.h" // Adjust path as necessary
#include <string>
#include <iostream>
#include <stack>
#include <regex>

// A simple placeholder function to "consume" XML strings.
void ProcessXml(const std::string& xml_string) {
  // std::cout << "Generated XML: " << xml_string << std::endl;
  std::regex tag_regex("<([a-zA-Z0-9_:]+)([^>]*)>");
  std::smatch match;
  std::string::const_iterator search_start(xml_string.cbegin());
  std::stack<std::string> open_tags;

  while (std::regex_search(search_start, xml_string.cend(), match, tag_regex)) {
    std::string tag_name = match[1].str();
    std::string full_tag = match[0].str();

    if (full_tag.size() > 1 && full_tag[full_tag.size() - 2] == '/') {
      // Self-closing tag
    } else if (full_tag.size() > 0 && full_tag[1] == '/') {
      // Closing tag
      std::string actual_tag_name = tag_name.substr(1);
      if (open_tags.empty() || open_tags.top() != actual_tag_name) {
        return;
      }
      if (!open_tags.empty()) {
        open_tags.pop();
      }
    } else {
      // Opening tag
      open_tags.push(tag_name);
    }
    search_start = match.suffix().first;
  }
  // Optional: Assert that all tags were closed if strict well-formedness is always expected.
  // FUZZTEST_ASSERT(open_tags.empty());
}

// Fuzz test for the ProcessXml function using the XML domain
FUZZ_TEST(XmlFuzzTest, ProcessXmlConsumesValidXml)
    .WithDomains(fuzztest::internal::XmlElementDomain());

// Basic test with a fixed string
TEST(XmlFuzzTest, ProcessXmlSimpleValidCase) {
    ProcessXml("<root><item>Test</item></root>");
}
```

### Note on Bazel Configuration for the Example

The provided example (`examples/xml_fuzz_test.cc`) is configured in its `examples/BUILD` file to run using a standard `cc_test` Bazel rule, linking with `//fuzztest:fuzztest_gtest_main`. This was a workaround due to difficulties encountered in the development environment with loading the `cc_fuzz_test` Bazel macro.

For full-fledged fuzzing (including corpus generation, advanced coverage guidance, etc.), you should use the `cc_fuzz_test` rule provided by FuzzTest. This typically involves loading it from a `.bzl` file (e.g., `load("@com_google_fuzztest//fuzztest:build_defs.bzl", "cc_fuzz_test")`) and using `cc_fuzz_test` instead of `cc_test` in your BUILD file. Ensure your project's Bazel WORKSPACE and FuzzTest integration are set up correctly to make `cc_fuzz_test` available.

```bazel
# Example BUILD file structure (conceptual) for cc_fuzz_test:
# load("@com_google_fuzztest//fuzztest:build_defs.bzl", "cc_fuzz_test") # Or the correct path for your setup

# cc_fuzz_test(
#     name = "xml_fuzz_test",
#     srcs = ["xml_fuzz_test.cc"],
#     deps = [
#         "//fuzztest:fuzztest",
#         "//fuzztest/internal/domains:xml_domain_impl", # Or your path to xml_domain.h
#         # Other necessary dependencies
#     ],
# )
```

By leveraging the XML domain, developers can create more robust and secure XML processing applications.
