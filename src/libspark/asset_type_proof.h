#ifndef FIRO_LIBSPARK_ASSET_TYPE_PROOF_H
#define FIRO_LIBSPARK_ASSET_TYPE_PROOF_H

#include "params.h"

namespace spark {

class AssetTypeProof{
public:
    inline std::size_t memoryRequired() const {
        return 2*GroupElement::memoryRequired() + 5*Scalar::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A);
        READWRITE(B);
        READWRITE(tx);
        READWRITE(ty);
        READWRITE(tz);
        READWRITE(uy);
        READWRITE(uz);
    }

public:
    GroupElement A, B;
    Scalar tx, ty, tz, uy, uz;
};
}

#endif
