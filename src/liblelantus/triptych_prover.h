#ifndef FIRO_LIBLELANTUS_TRIPTYCH_PROVER_H
#define FIRO_LIBLELANTUS_TRIPTYCH_PROVER_H

#include "lelantus_primitives.h"

namespace lelantus {

class TriptychProver{

public:
    TriptychProver(const GroupElement& g,
                    const std::vector<GroupElement>& h_gens,
                    const GroupElement& u,
                    std::size_t n, std::size_t m);

    void triptych_prove(
            const std::vector<GroupElement>& commits,
            const std::vector<GroupElement>& amount_commits,
            const Scalar& input_hash,
            const GroupElement& offset,
            std::size_t l,
            const Scalar& r,
            const Scalar& s,
            TriptychProof& proof_out);

private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    GroupElement u_;
    std::size_t n_;
    std::size_t m_;
};

}//namespace lelantus

#endif //FIRO_LIBLELANTUS_TRIPTYCH_PROVER_H
