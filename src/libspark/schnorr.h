#ifndef FIRO_LIBSPARK_SCHNORR_H
#define FIRO_LIBSPARK_SCHNORR_H

#include "schnorr_proof.h"
#include <secp256k1/include/MultiExponent.h>
#include "transcript.h"
#include "util.h"

namespace spark {

class Schnorr {
public:
    Schnorr(const std::vector<GroupElement>& G);

    void prove(const std::vector<Scalar>& y, const GroupElement& Y, SchnorrProof& proof);
    bool verify(const GroupElement& Y, SchnorrProof& proof);

private:
    Scalar challenge(const GroupElement& Y, const GroupElement& A);
    const std::vector<GroupElement>& G;
};

}

#endif
