import hypothesis.strategies as st

# Helper function for generating valid XML tag names
def tag_names():
    return st.text(alphabet=st.characters(min_codepoint=ord('a'), max_codepoint=ord('z')), min_size=1)

# Helper function for generating valid XML attribute names
def attribute_names():
    return st.text(alphabet=st.characters(min_codepoint=ord('a'), max_codepoint=ord('z')), min_size=1)

# Helper function for generating valid XML attribute values
def attribute_values():
    return st.text(alphabet=st.characters(min_codepoint=ord('a'), max_codepoint=ord('z'), whitelist_categories=('N', 'L', 'P', 'Z', 'S')), min_size=1)

# Helper function for generating XML attributes
def attributes():
    return st.dictionaries(attribute_names(), attribute_values())

# Helper function for generating XML content (text)
def content():
    return st.text(alphabet=st.characters(min_codepoint=ord('a'), max_codepoint=ord('z'), whitelist_categories=('N', 'L', 'P', 'Z', 'S')))

# Helper function to format attributes into a string
def format_attributes(attrs):
    if not attrs:
        return ""
    return " " + " ".join(f'{k}="{v}"' for k, v in attrs.items())

# Define the XML domain using RecursiveDomain
xml_domain = st.recursive(
    st.builds(lambda tag, attrs_str, children_content: f"<{tag}{attrs_str}>{children_content}</{tag}>",
              tag_names(),
              attributes().map(format_attributes),
              st.deferred(lambda: st.lists(xml_domain | content())).map("".join)),
    lambda children: st.builds(lambda tag, attrs_str, children_content: f"<{tag}{attrs_str}>{children_content}</{tag}>",
                               tag_names(),
                               attributes().map(format_attributes),
                               children.map("".join))
)

if __name__ == '__main__':
    # Example usage:
    # Generate a sample XML string
    sample_xml = xml_domain.example()
    print(sample_xml)
