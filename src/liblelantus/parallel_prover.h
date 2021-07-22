#ifndef FIRO_LIBLELANTUS_PARALLEL_PROVER_H
#define FIRO_LIBLELANTUS_PARALLEL_PROVER_H

#include "lelantus_primitives.h"

namespace lelantus {

class ParallelProver{

public:
    ParallelProver(const GroupElement& g, const GroupElement& h,
                    const std::vector<GroupElement>& h_gens, std::size_t n, std::size_t m);

    void parallel_commit(
            const std::vector<GroupElement>& commits_S,
            const std::vector<GroupElement>& commits_V,
            const GroupElement& offset_S,
            const GroupElement& offset_V,
            std::size_t l,
            const Scalar& rA,
            const Scalar& rB,
            const Scalar& rC,
            const Scalar& rD,
            std::vector<Scalar>& a,
            std::vector<Scalar>& Sk,
            std::vector<Scalar>& Vk,
            std::vector<Scalar>& sigma,
            ParallelProof& proof_out);

    void parallel_response(
            const std::vector<Scalar>& sigma,
            const std::vector<Scalar>& a,
            const Scalar& rA,
            const Scalar& rB,
            const Scalar& rC,
            const Scalar& rD,
            const Scalar& s,
            const Scalar& v,
            const std::vector<Scalar>& Sk,
            const std::vector<Scalar>& Vk,
            const Scalar& x,
            ParallelProof& proof_out);


private:
    GroupElement g_;
    GroupElement h_;
    std::vector<GroupElement> h_gens;
    std::size_t n_;
    std::size_t m_;
};

}//namespace lelantus

#endif //FIRO_LIBLELANTUS_PARALLEL_PROVER_H
