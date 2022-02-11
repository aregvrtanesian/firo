#ifndef FIRO_LIBSPARK_CONCISE_GROOTLE_PROOF_H
#define FIRO_LIBSPARK_CONCISE_GROOTLE_PROOF_H

#include "params.h"

namespace spark {

class ConciseGrootleProof {
public:

    inline std::size_t memoryRequired() const {
        return 2*GroupElement::memoryRequired() + X.size()*GroupElement::memoryRequired() + f.size()*Scalar::memoryRequired() + 2*Scalar::memoryRequired();
    }

    inline std::size_t memoryRequired(int n, int m) const {
        return 2*GroupElement::memoryRequired() + m*GroupElement::memoryRequired() + m*(n-1)*Scalar::memoryRequired() + 2*Scalar::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A);
        READWRITE(B);
        READWRITE(X);
        READWRITE(f);
        READWRITE(z);
        READWRITE(zX);
    }

public:
    GroupElement A;
    GroupElement B;
    std::vector<GroupElement> X;
    std::vector<Scalar> f;
    Scalar z;
    Scalar zX;
};

}

#endif
