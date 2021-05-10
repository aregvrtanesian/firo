
#ifndef FIRO_LIBLELANTUS_HIERARCHICAL_PROOF_H
#define FIRO_LIBLELANTUS_HIERARCHICAL_PROOF_H

#include "sigmaextended_proof.h"

namespace lelantus {
    
class HierarchicalProof{
public:

    inline std::size_t memoryRequired(uint64_t n_T, uint64_t m_T, uint64_t n_M, uint64_t m_M) const {
        GroupElement group; // for sizing

        return group.memoryRequired() * d.size()
               + P_1.memoryRequired(n_M, m_M)
               + P_2.memoryRequired(n_T, m_T);
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(d);
        READWRITE(P_1);
        READWRITE(P_2);
    }

    std::vector<GroupElement> d;
    SigmaExtendedProof P_1;
    SigmaExtendedProof P_2;

};
}//namespace lelantus

#endif //FIRO_LIBLELANTUS_HIERARCHICAL_PROOF_H
