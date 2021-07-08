#include "hierarchical_prover.h"
#include "hierarchical_verifier.h"

namespace lelantus {

HierarchicalVerifier::HierarchicalVerifier(
    const GroupElement& g,
    const GroupElement& h1,
    const GroupElement& h2,
    const std::vector<GroupElement>& h_gens_T,
    const std::vector<GroupElement>& h_gens_M,
    std::size_t n_T, std::size_t m_T,
    std::size_t n_M, std::size_t m_M)
    : g_(g)
    , h1_(h1)
    , h2_(h2)
    , h_T_(h_gens_T)
    , h_M_(h_gens_M)
    , n_T_(n_T)
    , m_T_(m_T)
    , n_M_(n_M)
    , m_M_(m_M)
{
}

void HierarchicalVerifier::verify(
    const std::vector<GroupElement>& C,
    HierarchicalProof& proof)
{
    // Size parameters
    const std::size_t T = (std::size_t)pow(n_T_, m_T_);
    const std::size_t M = (std::size_t)pow(n_M_, m_M_);

    // Transcript
    std::unique_ptr<ChallengeGenerator> transcript = std::make_unique<ChallengeGeneratorImpl<CHash256>>(1); 
    std::string domain("Hierarchical proof");
    std::vector<unsigned char> initialize(domain.begin(), domain.end());
    transcript->add(initialize);
    transcript->add(C);
    transcript->add(proof.d);

    // Verify the first one-of-many proof
    SigmaExtendedVerifier P_1_verifier(
        g_,
        h_M_,
        n_M_,
        m_M_
    );
    transcript->add(proof.P_1.A_);
    transcript->add(proof.P_1.B_);
    transcript->add(proof.P_1.C_);
    transcript->add(proof.P_1.D_);
    transcript->add(proof.P_1.Gk_);
    transcript->add(proof.P_1.Qk);
    Scalar x_1;
    transcript->get_challenge(x_1);

    std::vector<SigmaExtendedProof> proofs;
    proofs.reserve(1);
    proofs.resize(1);
    proofs[0] = proof.P_1;

    std::vector<Scalar> serials;
    serials.reserve(1);
    serials.resize(1);
    serials[0] = Scalar(uint64_t(0));

    if (!P_1_verifier.batchverify(proof.d, x_1, serials, proofs)) {
        throw std::runtime_error("Failed first proof!");
    }

    transcript->add(proof.P_1.f_);
    transcript->add(proof.P_1.ZA_);
    transcript->add(proof.P_1.ZC_);
    transcript->add(proof.P_1.zR_);
    transcript->add(proof.P_1.zV_);

    // Get the challenge vector
    std::vector<Scalar> x;
    x.reserve(M);
    x.resize(M);
    for (std::size_t i = 0; i < M; i++) {
        transcript->get_challenge(x[i]);
    }

    // Compute offset digests
    GroupElement D_ = digest(x, proof.d);
    std::vector<GroupElement> D;
    D.reserve(T);
    D.resize(T);
    for (std::size_t i = 0; i < T; i++) {
        std::vector<GroupElement> C_(C.begin() + i*M, C.begin() + (i + 1)*M);
        D[i] = D_ + digest(x, C_).inverse();
    }

    // Verify the second one-of-many proof
    SigmaExtendedVerifier P_2_verifier(
        g_,
        h_T_,
        n_T_,
        m_T_
    );
    transcript->add(proof.P_2.A_);
    transcript->add(proof.P_2.B_);
    transcript->add(proof.P_2.C_);
    transcript->add(proof.P_2.D_);
    transcript->add(proof.P_2.Gk_);
    transcript->add(proof.P_2.Qk);
    Scalar x_2;
    transcript->get_challenge(x_2);

    proofs[0] = proof.P_2;
    serials[0] = Scalar(uint64_t(0));

    if (!P_2_verifier.batchverify(D, x_2, serials, proofs)) {
        throw std::runtime_error("Failed second proof!");
    }
}

GroupElement HierarchicalVerifier::digest(
    const std::vector<Scalar>& scalars,
    const std::vector<GroupElement>& points)
{
    // Size checks
    if (scalars.size() != points.size()) {
        throw std::invalid_argument("Digest requires equal vector input sizes");
    }

    // Compute weighted sum as a multiscalar multiplication
    secp_primitives::MultiExponent mult(points, scalars);
    return mult.get_multiple();
}


}