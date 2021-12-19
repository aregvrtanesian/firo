#ifndef FIRO_LIBSPARK_GROOTLE_PROOF_H
#define FIRO_LIBSPARK_GROOTLE_PROOF_H

#include "params.h"

namespace spark {

class GrootleProof {
public:

    inline std::size_t memoryRequired() const {
        return 4*GroupElement::memoryRequired() + Gs.size()*GroupElement::memoryRequired() + Gv.size()*GroupElement::memoryRequired() + f.size()*Scalar::memoryRequired() + 4*Scalar::memoryRequired();
    }

    inline std::size_t memoryRequired(int n, int m) const {
        return 4*GroupElement::memoryRequired() + 2*m*GroupElement::memoryRequired() + m*(n-1)*Scalar::memoryRequired() + 4*Scalar::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A);
        READWRITE(B);
        READWRITE(C);
        READWRITE(D);
        READWRITE(Gs);
        READWRITE(Gv);
        READWRITE(f);
        READWRITE(zA);
        READWRITE(zC);
        READWRITE(zS);
        READWRITE(zV);
    }

public:
    GroupElement A;
    GroupElement B;
    GroupElement C;
    GroupElement D;
    std::vector<GroupElement> Gs;
    std::vector<GroupElement> Gv;
    std::vector<Scalar> f;
    Scalar zA;
    Scalar zC;
    Scalar zS;
    Scalar zV;
};

}

#endif
