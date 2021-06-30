#ifndef FIRO_LIBLELANTUS_TRIPTYCH_PROOF_H
#define FIRO_LIBLELANTUS_TRIPTYCH_PROOF_H

#include <vector>
#include "params.h"

namespace lelantus {

class TriptychProof{
public:
    TriptychProof() = default;

    inline std::size_t memoryRequired() const {
        return B_.memoryRequired() * 6 // J, K, A, B, C, D
               + B_.memoryRequired() * X_.size() * 2 // {X}, {Y}
               + zA_.memoryRequired() * f_.size() // {f}
               + zA_.memoryRequired() * 3; // zA, zC, z
    }

    inline std::size_t memoryRequired(int n, int m) const {
        return B_.memoryRequired() * 6 // J, K, A, B, C, D
               + B_.memoryRequired() * m * 2 // {X}, {Y}
               + zA_.memoryRequired() * m*(n - 1) // {f}
               + zA_.memoryRequired() * 3; // zA, zC, z
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(J_);
        READWRITE(K_);
        READWRITE(A_);
        READWRITE(B_);
        READWRITE(C_);
        READWRITE(D_);
        READWRITE(X_);
        READWRITE(Y_);
        READWRITE(f_);
        READWRITE(zA_);
        READWRITE(zC_);
        READWRITE(z_);
    }

public:
    GroupElement J_;
    GroupElement K_;
    GroupElement A_;
    GroupElement B_;
    GroupElement C_;
    GroupElement D_;
    std::vector<GroupElement> X_;
    std::vector<GroupElement> Y_;
    std::vector<Scalar> f_;
    Scalar zA_;
    Scalar zC_;
    Scalar z_;
};

} //namespace lelantus

#endif //FIRO_LIBLELANTUS_TRIPTYCH_PROOF_H
