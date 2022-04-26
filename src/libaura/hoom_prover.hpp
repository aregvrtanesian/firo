#include <math.h>
#include <iostream>

namespace aura {

    template<class Exponent, class GroupElement>
    HOOMProver<Exponent, GroupElement>::HOOMProver(const GroupElement& g,
                        const std::vector<GroupElement>& h_gens,
                        int t_n, int t_m, int m_n, int m_m)
                        : g_(g)
                        , h_(h_gens)
                        , t_n_(t_n)
                        , t_m_(t_m)
                        , m_n_(m_n)
                        , m_m_(m_m) {
    }

    template<class Exponent, class GroupElement>
    void HOOMProver<Exponent, GroupElement>::proof(const std::vector<GroupElement>& commits,
               const int& l,
               const Exponent& r,
               HOOMProof<Exponent, GroupElement>& proof_out) {
        Exponent y;
        SigmaPrimitives<Exponent, GroupElement>::generate_challenge(commits, y);
        int t_ = pow(t_n_, t_m_);
        int m_ = pow(m_n_, m_m_);
        std::vector<secp_primitives::Scalar> r_;
        r_.resize(m_);
        for (int k = 0; k < m_; ++k) {
            r_[k].randomize();
        }
        proof_out.d_.resize(m_);
        int ptr = l / m_ * m_;
        for (int k = 0; k < m_; ++k) {
            proof_out.d_[k] = commits[ptr + k] + h_[0] * r_[k];
        }

        secp_primitives::GroupElement c;
        secp_primitives::Scalar zero(uint64_t(0));
        aura::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> d_prover(g_, h_, m_n_, m_m_);
        d_prover.proof(proof_out.d_, l % m_, r_[l % m_] + r, true, y, proof_out.d_Proof_);
        std::vector<secp_primitives::Scalar> x;
        x.resize(m_);
        SigmaPrimitives<Exponent, GroupElement>::generate_challenge({h_[0] * y}, x[0]);
        secp_primitives::Scalar xsum = r_[0] * x[0];
        for (int k = 1; k < m_; ++k) {
            SigmaPrimitives<Exponent, GroupElement>::generate_challenge({h_[0] * x[k - 1]}, x[k]);
            xsum += r_[k] * x[k];
        }
        std::vector<GroupElement> D_;
        D_.resize(t_);
        GroupElement D;
        D = SigmaPrimitives<Exponent, GroupElement>::HelperFunction(proof_out.d_, x);
        for (int k = 0; k < t_; ++k) {
            D_[k] = D + SigmaPrimitives<Exponent, GroupElement>::HelperFunction({commits.begin() + k * m_, commits.begin() + (k + 1) * m_}, x).inverse();
        }
        aura::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> D_prover(g_, h_, t_n_, t_m_);
        D_prover.proof(D_, l / m_, xsum, true, x[m_ - 1], proof_out.D_Proof_);
    }



} // namespace aura
