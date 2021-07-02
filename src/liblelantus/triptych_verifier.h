#ifndef FIRO_LIBLELANTUS_TRIPTYCH_VERIFIER_H
#define FIRO_LIBLELANTUS_TRIPTYCH_VERIFIER_H

#include "lelantus_primitives.h"

namespace lelantus {

class TriptychVerifier{

public:
    TriptychVerifier(const GroupElement& g,
                      const std::vector<GroupElement>& h_gens,
                      const GroupElement& u,
                      std::size_t n_, std::size_t m_);

    // Verify a single one-of-many proof
    // In this case, there is an implied input set size
    bool singleverify(const std::vector<GroupElement>& commits,
                     const std::vector<GroupElement>& amount_commits,
                     const Scalar& input_hash,
                     const GroupElement& offset,
                     const TriptychProof& proof) const;

    // Verify a single one-of-many proof
    // In this case, there is a specified set size
    bool singleverify(const std::vector<GroupElement>& commits,
                     const std::vector<GroupElement>& amount_commits,
                     const Scalar& input_hash,
                     const GroupElement& offset,
                     const size_t setSize,
                     const TriptychProof& proof) const;

    // Verify a batch of one-of-many proofs from the same transaction
    // In this case, there is an implied input set size
    bool batchverify(const std::vector<GroupElement>& commits,
                     const std::vector<GroupElement>& amount_commits,
                     const Scalar& input_hash,
                     const std::vector<GroupElement>& offsets,
                     const std::vector<TriptychProof>& proofs) const;
    // Verify a general batch of one-of-many proofs
    // In this case, each proof has a specified set size
    bool batchverify(const std::vector<GroupElement>& commits,
                     const std::vector<GroupElement>& amount_commits,
                     const Scalar& input_hash,
                     const std::vector<GroupElement>& offsets,
                     const std::vector<size_t>& setSizes,
                     const std::vector<TriptychProof>& proofs) const;

private:
    // Utility function that actually performs verification
    bool verify(const std::vector<GroupElement>& commits,
                     const std::vector<GroupElement>& amount_commits,
                     const Scalar& input_hash,
                     const std::vector<GroupElement>& offsets,
                     const std::vector<size_t>& setSizes,
                     const bool specifiedSetSizes,
                     const std::vector<TriptychProof>& proofs) const;
    //auxiliary functions
    bool membership_checks(const TriptychProof& proof) const;
    bool compute_fs(
            const TriptychProof& proof,
            const Scalar& x,
            std::vector<Scalar>& f_) const;
    void compute_batch_fis(
            Scalar& f_sum,
            const Scalar& f_i,
            int j,
            const std::vector<Scalar>& f,
            const Scalar& w3,
            const Scalar& mu,
            std::vector<Scalar>::iterator& ptr_commit,
            std::vector<Scalar>::iterator& ptr_amount_commit,
            std::vector<Scalar>::iterator start_ptr,
            std::vector<Scalar>::iterator end_ptr) const;

private:
    GroupElement g_;
    std::vector<GroupElement> h_;
    GroupElement u_;
    std::size_t n;
    std::size_t m;
};

} // namespace lelantus

#endif //FIRO_LIBLELANTUS_TRIPTYCH_VERIFIER_H
