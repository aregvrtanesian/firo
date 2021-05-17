#ifndef FIRO_LIBLELANTUS_HIERARCHICAL_VERIFIER_H
#define FIRO_LIBLELANTUS_HIERARCHICAL_VERIFIER_H

#include "lelantus_primitives.h"
#include "sigmaextended_verifier.h"
#include "challenge_generator_impl.h"

namespace lelantus {

class HierarchicalVerifier{

public:
    HierarchicalVerifier(
        const GroupElement& g,
        const GroupElement& h1,
        const GroupElement& h2,
        const std::vector<GroupElement>& h_gens_T,
        const std::vector<GroupElement>& h_gens_M,
        std::size_t n_T, std::size_t m_T,
        std::size_t n_M, std::size_t m_M);

    void verify(
        const std::vector<GroupElement>& C,
        HierarchicalProof& proof);

    GroupElement digest(
        const std::vector<Scalar>& scalars,
        const std::vector<GroupElement>& points);

private:
    GroupElement g_;
    GroupElement h1_;
    GroupElement h2_;
    std::vector<GroupElement> h_T_;
    std::vector<GroupElement> h_M_;
    std::size_t n_T_;
    std::size_t m_T_;
    std::size_t n_M_;
    std::size_t m_M_;
};

}//namespace lelantus

#endif //FIRO_LIBLELANTUS_HIERARCHICAL_VERIFIER_H
