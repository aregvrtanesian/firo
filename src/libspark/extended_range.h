#ifndef FIRO_LIBSPARK_EXTENDED_RANGE_H
#define FIRO_LIBSPARK_EXTENDED_RANGE_H

#include "extended_range_proof.h"
#include <secp256k1/include/MultiExponent.h>
#include "transcript.h"
#include "util.h"

namespace spark {
    
class ExtendedRange {
public:
    ExtendedRange(
        const GroupElement& F,
        const GroupElement& G,
        const GroupElement& H,
        const std::vector<GroupElement>& Gi,
        const std::vector<GroupElement>& Hi,
        const std::size_t N);
    
    void prove(const std::vector<Scalar>& a, const std::vector<Scalar>& v, const std::vector<Scalar>& r, const std::vector<GroupElement>& C, ExtendedRangeProof& proof);
    bool verify(const std::vector<GroupElement>& C, const ExtendedRangeProof& proof); // single proof
    bool verify(const std::vector<std::vector<GroupElement>>& C, const std::vector<ExtendedRangeProof>& proofs); // batch of proofs

private:
    GroupElement F;
    GroupElement G;
    GroupElement H;
    std::vector<GroupElement> Gi;
    std::vector<GroupElement> Hi;
    std::size_t N;
    Scalar TWO_N_MINUS_ONE;
};

}

#endif
