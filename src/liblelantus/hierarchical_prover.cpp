#include "hierarchical_prover.h"

namespace lelantus {

HierarchicalProver::HierarchicalProver(
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

void HierarchicalProver::proof(
    const std::vector<GroupElement>& C,
    int L,
    const Scalar& v,
    const Scalar& r,
    HierarchicalProof& proof_out)
{
    // Size parameters
    const std::size_t T = (std::size_t)pow(n_T_, m_T_);
    const std::size_t M = (std::size_t)pow(n_M_, m_M_);

    // Verify commitment and secret index
    const std::size_t k = L / M;
    const std::size_t l = L % M;
    if (!(LelantusPrimitives::double_commit(g_, Scalar(uint64_t(0)), h1_, v, h2_, r) == C[k*M + l])) {
        throw std::invalid_argument("Bad known commitment");
    }

    // Transcript
    unique_ptr<ChallengeGenerator> transcript = std::make_unique<ChallengeGeneratorImpl<CHash256>>(1); 
    std::string domain("Hierarchical proof");
    std::vector<unsigned char> initialize(domain.begin(), domain.end());
    transcript->add(initialize);
    transcript->add(C);

    // Blinding factors
    std::vector<Scalar> r_blinders;
    r_blinders.reserve(M);
    r_blinders.resize(M);
    std::vector<Scalar> v_blinders;
    v_blinders.reserve(M);
    v_blinders.resize(M);
    for (std::size_t i = 0; i < M; i++) {
        r_blinders[i].randomize();
        v_blinders[i].randomize();
    }

    // Build the offset subset
    proof_out.d.reserve(M);
    proof_out.d.resize(M);
    for (std::size_t i = 0; i < M; i++) {
        proof_out.d[i] = C[k*M + i] + h1_*v_blinders[i] + h2_*r_blinders[i];
    }
    transcript->add(proof_out.d);

    // Construct the first one-of-many proof
    SigmaExtendedProver P_1_prover(
        g_,
        h_M_,
        n_M_,
        m_M_
    );
    proof_out.P_1 = build_sigma(P_1_prover, transcript, n_M_, m_M_, proof_out.d, l, v + v_blinders[l], r + r_blinders[l]);

    // Get the challenge vector
    std::vector<Scalar> x;
    x.reserve(M);
    x.resize(M);
    for (std::size_t i = 0; i < M; i++) {
        transcript->get_challenge(x[i]);
    }

    // Compute offset digests
    GroupElement D_ = digest(x, proof_out.d);
    std::vector<GroupElement> D;
    D.reserve(T);
    D.resize(T);
    for (std::size_t i = 0; i < T; i++) {
        std::vector<GroupElement> C_(C.begin() + i*M, C.begin() + (i + 1)*M);
        D[i] = D_ + digest(x, C_).inverse();
    }
    Scalar v_blinder(uint64_t(0));
    Scalar r_blinder(uint64_t(0));
    for (std::size_t i = 0; i < M; i++) {
        v_blinder += x[i]*v_blinders[i];
        r_blinder += x[i]*r_blinders[i];
    }

    // Construct the second one-of-many proof
    SigmaExtendedProver P_2_prover(
        g_,
        h_T_,
        n_T_,
        m_T_
    );
    proof_out.P_2 = build_sigma(P_2_prover, transcript, n_T_, m_T_, D, k, v_blinder, r_blinder);
}

GroupElement HierarchicalProver::digest(
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

SigmaExtendedProof HierarchicalProver::build_sigma(
    SigmaExtendedProver& prover,
    unique_ptr<ChallengeGenerator>& transcript,
    const std::size_t n,
    const std::size_t m,
    const std::vector<GroupElement>& commits,
    const std::size_t l,
    const Scalar& v,
    const Scalar& r)
{
    // Prover state
    Scalar rA, rB, rC, rD;
    rA.randomize();
    rB.randomize();
    rC.randomize();
    rD.randomize();
    std::vector<Scalar> a, sigma;
    a.reserve(n * m);
    a.resize(n * m);
    std::vector<Scalar> Tk, Pk, Yk;
    Tk.reserve(m);
    Tk.resize(m);
    Pk.reserve(m);
    Pk.resize(m);
    Yk.reserve(m);
    Yk.resize(m);

    // Initial proof
    SigmaExtendedProof proof;
    prover.sigma_commit(
        commits,
        l,
        rA, rB, rC, rD,
        a, Tk, Pk, Yk,
        sigma,
        proof
    );

    // Update transcript
    transcript->add(proof.A_);
    transcript->add(proof.B_);
    transcript->add(proof.C_);
    transcript->add(proof.D_);
    transcript->add(proof.Gk_);
    transcript->add(proof.Qk);

    // Challenge
    Scalar challenge;
    transcript->get_challenge(challenge);

    // Final proof
    prover.sigma_response(
        sigma, a,
        rA, rB, rC, rD,
        v, r,
        Tk, Pk,
        challenge,
        proof
    );

    // Update transcript
    transcript->add(proof.f_);
    transcript->add(proof.ZA_);
    transcript->add(proof.ZC_);
    transcript->add(proof.zR_);
    transcript->add(proof.zV_);

    return proof;
}

}