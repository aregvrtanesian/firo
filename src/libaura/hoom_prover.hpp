#include <math.h>
namespace aura {

    template<class Exponent, class GroupElement>
    HierarchicOOMProver(const GroupElement& g,
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
    void proof(const std::vector<GroupElement>& commits,
               const Exponent& l,
               HOOMProof<Exponent, GroupElement>& proof_out) {
        int t_ = pow(t_n_, t_m_);
        int m_ = pow(m_n_, m_m_);
        std::vector<Exponent> r;
        r.resize(m_);
        for (int k = 0; k < m_; ++k) {
            r[k].randomize();
        }
        proof_out.d_.resize(m_);
        int ptr = l / m_ * m_;
        for (int k = 0; k < m_; ++k) {
            d_[k] = commits[ptr + k] + h_[0] * r[k];
        }

        aura::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> d_prover(g_, h_, m_n_, m_m_);
        aura::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> d_proof(m_n_, m_m_);
        d_prover.proof(d, l - ptr, false, d_proof);
        proof_out.d_Proof_ = d_proof;
        std::vector<Exponent> x;
        x.resize(m_);

        std::vector<GroupElement> group_elements = {g, h_[0] * t_n_, h_[0] * t_m_, h_[0] * m_n_, h_[0] * m_m_};
        group_elements.insert(group_elements.end(), proof_out.d_.begin(), proof_out.d_.end());
        proof_out.D_Proof_.resize(t_);
        for (int k = 0; k < m_; ++k) {
            SigmaPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, x[k]);
            group_elements.pushback(h_[0] * x[k]);
        }
        std::vector<GroupElement> C_;
        C_.resize(m_);
        std::vector<GroupElement> D_;
        D_.resize(t_);
        GroupElement D;
        D = SigmaPrimitives<Exponent, GroupElement>::HelperFunction(proof_out.d_, x);
        for (int k = 0; k < t_; ++k) {
            std::copy(commits.begin() + k * m_, commits.begin() + (k + 1) * m_ - 1, C_.begin())
            D_[k] = SigmaPrimitives<Exponent, GroupElement>::HelperFunction(C_, x) + D * -1;
        }

        aura::SigmaPlusProver<secp_primitives::Scalar,secp_primitives::GroupElement> D_prover(g_, h_, t_n_, t_m_);
        aura::SigmaPlusProof<secp_primitives::Scalar,secp_primitives::GroupElement> D_proof(t_n_, t_m_);
        D_prover.proof(D_, l / m_, false, D_proof);
        proof_out.D_Proof_ = D_proof;

    }

} // namespace aura
