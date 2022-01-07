#include "util.h"
#include <string.h>

namespace spark {

using namespace secp_primitives;

// Need to assert that we get the correct hash output size
static_assert(CSHA256::OUTPUT_SIZE == 32);

// Produce a uniformly-sampled group element from a label
GroupElement SparkUtils::hash_generator(const std::string label) {
    CSHA256 hasher;

    // Write the mode
    hasher.Write(&HASH_MODE_GROUP_GENERATOR, sizeof(HASH_MODE_GROUP_GENERATOR));

    // Write the label
    std::vector<unsigned char> bytes(label.begin(), label.end());
    hasher.Write(bytes.data(), bytes.size());

    return hash_to_group(hasher);
}

// Finalize a hash and map uniformly to a scalar
Scalar SparkUtils::hash_to_scalar(CSHA256& _hasher) {
    CSHA256 hasher = _hasher;

    unsigned char hash[32];
    unsigned char counter = 0;
    CSHA256 hasher_counter, hasher_finalize;

    while (1) {
        // Ratchet the counter
        counter++;

        // Prepare temporary state for counter testing
        hasher_counter = hasher;

        // Embed the counter
        hasher_counter.Write(&counter, sizeof(counter));

        // Finalize the hash with a temporary state
        hasher_finalize = hasher_counter;
        hasher_finalize.Finalize(hash);

        // Check for scalar validity
        Scalar candidate;
        try {
            candidate.deserialize(hash);
            return candidate;
        } catch (...) {
            // Continue
        }
    }
}

// Finalize a hash and map uniformly to a group element
GroupElement SparkUtils::hash_to_group(CSHA256& _hasher) {
    CSHA256 hasher = _hasher;

    // We need an extra bit of data for the sign bit, so we use a second hash
    unsigned char hash[64];
    unsigned char counter = 0;
    CSHA256 hasher_counter, hasher_finalize;

    while (1) {
        // Ratchet the counter
        counter++;
        hasher_counter = hasher;
        hasher_counter.Write(&counter, sizeof(counter));

        // Compute both hashes using the counter, adding a separate additional flag for each
        hasher_finalize = hasher_counter;
        const unsigned char ZERO = 0;
        hasher_finalize.Write(&ZERO, sizeof(ZERO));
        hasher_finalize.Finalize(hash);

        hasher_finalize = hasher_counter;
        const unsigned char ONE = 1;
        hasher_finalize.Write(&ONE, sizeof(ONE));
        hasher_finalize.Finalize(hash + 32*sizeof(unsigned char));

        // Assemble the serialized input:
        //   bytes 0..31: x coordinate
        //   byte 32: even/odd
        //   byte 33: zero (this point is not infinity)
        unsigned char candidate_bytes[34];
        memcpy(candidate_bytes, hash, 33*sizeof(unsigned char));
        memcpy(candidate_bytes + 33, &ONE, sizeof(unsigned char));

        // Check for group element validity
        GroupElement candidate;
        try {
            candidate.deserialize(candidate_bytes);
            return candidate;
        } catch (...) {
            // Continue
        }
    }
}

}
