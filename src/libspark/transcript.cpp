#include "transcript.h"
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include "../../crypto/sha256.h"
namespace spark {

using namespace secp_primitives;

const std::size_t SCALAR_ENCODING = 32;

// Flags for transcript operations
const unsigned char FLAG_DOMAIN = 0;
const unsigned char FLAG_DATA = 1;
const unsigned char FLAG_VECTOR = 2;
const unsigned char FLAG_CHALLENGE = 3;

// Initialize a transcript with a domain separator
Transcript::Transcript(const std::string domain) {
    include_flag(FLAG_DOMAIN);
    include_label(domain);
}

// Add a group element
void Transcript::add(const std::string label, const GroupElement& group_element) {
    std::vector<unsigned char> data;
    data.resize(GroupElement::serialize_size);
    group_element.serialize(data.data());

    include_flag(FLAG_DATA);
    include_label(label);
    include_data(data);
}

// Add a vector of group elements
void Transcript::add(const std::string label, const std::vector<GroupElement>& group_elements) {
    include_flag(FLAG_VECTOR);
    size(group_elements.size());
    include_label(label);
    for (std::size_t i = 0; i < group_elements.size(); i++) {
        std::vector<unsigned char> data;
        data.resize(GroupElement::serialize_size);
        group_elements[i].serialize(data.data());
        include_data(data);
    }
}

// Add a scalar
void Transcript::add(const std::string label, const Scalar& scalar) {
    std::vector<unsigned char> data;
    data.resize(SCALAR_ENCODING);
    scalar.serialize(data.data());

    include_flag(FLAG_DATA);
    include_label(label);
    include_data(data);
}

// Add a vector of scalars
void Transcript::add(const std::string label, const std::vector<Scalar>& scalars) {
    include_flag(FLAG_VECTOR);
    size(scalars.size());
    include_label(label);
    for (std::size_t i = 0; i < scalars.size(); i++) {
        std::vector<unsigned char> data;
        data.resize(SCALAR_ENCODING);
        scalars[i].serialize(data.data());
        include_data(data);
    }
}

// Add arbitrary data
void Transcript::add(const std::string label, const std::vector<unsigned char>& data) {
    include_flag(FLAG_DATA);
    include_label(label);
    include_data(data);
}

// Produce a challenge
Scalar Transcript::challenge() {
    unsigned char hash[state.OUTPUT_SIZE];
    unsigned char counter = 0;
    CSHA256 state_counter, state_finalize;

    while (1) {
        // Prepare temporary state for counter testing
        state_counter = state;

        // Embed the counter
        include_flag(FLAG_CHALLENGE);
        state_counter.Write(&counter, sizeof(counter));

        // Finalize the hash with a temporary state
        state_finalize = state_counter;
        state_finalize.Finalize(hash);

        // Check for scalar validity
        Scalar candidate(hash);
        if (candidate.isMember()) {
            state = state_counter;
            return candidate;
        }

        counter++;
    }
}

// Encode and include a size
void Transcript::size(const std::size_t size_) {
    Scalar size_scalar(size_);
    std::vector<unsigned char> size_data;
    size_data.resize(SCALAR_ENCODING);
    size_scalar.serialize(size_data.data());
    state.Write(size_data.data(), size_data.size());
}

// Include a flag
void Transcript::include_flag(const unsigned char flag) {
    state.Write(&flag, sizeof(flag));
}

// Encode and include a label
void Transcript::include_label(const std::string label) {
    std::vector<unsigned char> bytes(label.begin(), label.end());
    include_data(bytes);
}

// Encode and include data
void Transcript::include_data(const std::vector<unsigned char>& data) {
    // Include size
    size(data.size());

    // Include data
    state.Write(data.data(), data.size());
}

}
