#ifndef FIRO_LIBSPARK_EXTENDED_RANGE_PROOF_H
#define FIRO_LIBSPARK_EXTENDED_RANGE_PROOF_H

#include "params.h"

namespace spark {
    
class ExtendedRangeProof{
public:

    static inline int int_log2(std::size_t number) {
        assert(number != 0);

        int l2 = 0;
        while ((number >>= 1) != 0)
            l2++;

        return l2;
    }

    inline std::size_t memoryRequired() const {
        return 3*GroupElement::memoryRequired() + 4*Scalar::memoryRequired() + ip_L.size()*GroupElement::memoryRequired() + ip_R.size()*GroupElement::memoryRequired();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(A);
        READWRITE(ip_A);
        READWRITE(ip_B);
        READWRITE(ip_r1);
        READWRITE(ip_s1);
        READWRITE(ip_delta1);
        READWRITE(ip_delta1_);
        READWRITE(ip_L);
        READWRITE(ip_R);
    }

    GroupElement A, ip_A, ip_B;
    Scalar ip_r1, ip_s1, ip_delta1, ip_delta1_;
    std::vector<GroupElement> ip_L, ip_R;
};
}

#endif
