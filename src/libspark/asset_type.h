#ifndef FIRO_LIBSPARK_ASSET_TYPE_H
#define FIRO_LIBSPARK_ASSET_TYPE_H

#include "asset_type_proof.h"
#include <secp256k1/include/MultiExponent.h>
#include "transcript.h"
#include "util.h"

namespace spark {

class AssetType {
public:
    AssetType(const GroupElement& F, const GroupElement& G, const GroupElement& H);

    void prove(const Scalar& x, const std::vector<Scalar>& y, const std::vector<Scalar>& z, const std::vector<GroupElement>& C, AssetTypeProof& proof);
    bool verify(const std::vector<GroupElement>& C, AssetTypeProof& proof);

private:
    Scalar challenge(const std::vector<GroupElement>& C, const GroupElement& A, const GroupElement& B);
    const GroupElement& F;
    const GroupElement& G;
    const GroupElement& H;
};

}

#endif
