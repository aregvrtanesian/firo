#ifndef FIRO_SPARK_UTIL_H
#define FIRO_SPARK_UTIL_H
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include "../../crypto/sha256.h"
#include "../util.h"

namespace spark {

using namespace secp_primitives;

// Base protocol separator
const std::string LABEL_PROTOCOL = "SPARK";

// All hash operations have a mode flag to separate their use cases
const unsigned char HASH_MODE_TRANSCRIPT = 0; // a Fiat-Shamir transcript
const unsigned char HASH_MODE_GROUP_GENERATOR = 1; // a prime-order group generator derived from a label
const unsigned char HASH_MODE_FUNCTION = 2; // a scalar-codomain hash function derived from a label
const unsigned char HASH_MODE_KDF = 3; // a scalar-codomain key derivation function derived from a label

// Generator labels
const std::string LABEL_GENERATOR_F = "F";
const std::string LABEL_GENERATOR_G = "G";
const std::string LABEL_GENERATOR_H = "H";
const std::string LABEL_GENERATOR_U = "U";
const std::string LABEL_GENERATOR_G_RANGE = "G_RANGE";
const std::string LABEL_GENERATOR_H_RANGE = "H_RANGE";
const std::string LABEL_GENERATOR_G_GROOTLE = "G_GROOTLE";

// KDF labels
const std::string LABEL_KDF_SPEND = "SPEND";
const std::string LABEL_KDF_INCOMING = "INCOMING_VIEW";
const std::string LABEL_KDF_FULL = "FULL_VIEW";

// Component transcript labels
const std::string LABEL_TRANSCRIPT_EXTENDED_RANGE_PROOF = "EXTENDED_RANGE_PROOF";
const std::string LABEL_TRANSCRIPT_ASSET_TYPE_PROOF = "ASSET_TYPE_PROOF";
const std::string LABEL_TRANSCRIPT_SCHNORR_PROOF = "SCHNORR_PROOF";

class SparkUtils {
public:
    // Protocol-level hash functions
    static GroupElement hash_generator(const std::string label);

    // Key derivation functions
    static Scalar kdf_spend(const Scalar&);
    static Scalar kdf_incoming_view(const Scalar&);
    static Scalar kdf_full_view(const Scalar&);

private:
    // Get a hash in the proper set from raw input
    static Scalar hash_to_scalar(CSHA256&);
    static GroupElement hash_to_group(CSHA256&);
};

}

#endif
