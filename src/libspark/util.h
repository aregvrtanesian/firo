#ifndef FIRO_SPARK_UTIL_H
#define FIRO_SPARK_UTIL_H
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include "../../crypto/sha256.h"

namespace spark {

using namespace secp_primitives;

// All hash operations have a mode flag to separate their use cases
const unsigned char HASH_MODE_TRANSCRIPT = 0; // a Fiat-Shamir transcript
const unsigned char HASH_MODE_GROUP_GENERATOR = 1; // a prime-order group generator derived from a label
const unsigned char HASH_MODE_FUNCTION = 2; // a scalar-codomain hash function derived from a label


class SparkUtils {
public:
    // Protocol-level hash functions
    static GroupElement hash_generator(const std::string label);

private:
    // Get a hash in the proper set from raw input
    static Scalar hash_to_scalar(CSHA256&);
    static GroupElement hash_to_group(CSHA256&);
};

}

#endif
